// Package restore brings a stored dump into a scratch database: download with
// sha256 check, age decryption, scratch start and pg_restore. verify, scan and
// mask all build on it.
package restore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/scratch"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

// DumpFile is the name of the decrypted archive inside the work dir.
const DumpFile = "dump.pgc"

// Object describes what to fetch.
type Object struct {
	Key       string // storage key of the stored object
	SHA256    string // expected sha256 of the stored bytes
	SizeBytes int64
	Encrypted bool
}

// ErrChecksum is wrapped by Fetch when the stored object does not match.
var ErrChecksum = errors.New("checksum mismatch")

// ErrDecrypt is wrapped by Fetch when decryption fails (wrong key, truncated, tampered).
var ErrDecrypt = errors.New("decrypt failed")

// FetchResult reports what Fetch observed.
type FetchResult struct {
	SHA256    string
	SizeBytes int64
	DumpPath  string // dir/dump.pgc on success
}

// Fetch downloads obj into dir, verifies sha256 and size, and decrypts it to
// dir/dump.pgc. Errors wrap ErrChecksum or ErrDecrypt for those failures.
func Fetch(ctx context.Context, store *storage.Store, obj Object, ids []age.Identity, dir string) (*FetchResult, error) {
	objPath := filepath.Join(dir, "object")
	size, sum, err := download(ctx, store, obj.Key, objPath)
	if err != nil {
		return nil, err
	}
	res := &FetchResult{SHA256: sum, SizeBytes: size}
	if sum != obj.SHA256 || size != obj.SizeBytes {
		return res, fmt.Errorf("%w: sha256 %s… (%d bytes) does not match manifest %s… (%d bytes)",
			ErrChecksum, short(sum), size, short(obj.SHA256), obj.SizeBytes)
	}
	dumpPath := filepath.Join(dir, DumpFile)
	if obj.Encrypted {
		if len(ids) == 0 {
			return res, fmt.Errorf("%w: no age identity to decrypt with", ErrDecrypt)
		}
		if err := decryptFile(objPath, dumpPath, ids); err != nil {
			return res, fmt.Errorf("%w: %v", ErrDecrypt, err)
		}
		_ = os.Remove(objPath)
	} else if err := os.Rename(objPath, dumpPath); err != nil {
		return res, err
	}
	res.DumpPath = dumpPath
	return res, nil
}

// RestoreResult reports a pg_restore run.
type RestoreResult struct {
	Duration time.Duration
	Errors   []string // pg_restore "error:" lines (credential-free)
	Err      error    // pg_restore exit error, if any
}

// OK reports whether pg_restore finished without errors.
func (r *RestoreResult) OK() bool { return r.Err == nil && len(r.Errors) == 0 }

// Detail summarizes the failure.
func (r *RestoreResult) Detail() string {
	if len(r.Errors) > 0 {
		errs := r.Errors
		if len(errs) > 3 {
			errs = append(errs[:3:3], fmt.Sprintf("(+%d more)", len(r.Errors)-3))
		}
		return strings.Join(errs, " | ")
	}
	if r.Err != nil {
		return fmt.Sprintf("pg_restore: %v", r.Err)
	}
	return ""
}

// DefaultJobs is the pg_restore parallelism when the config says 0.
func DefaultJobs(configured int) int {
	if configured > 0 {
		return configured
	}
	return min(4, runtime.NumCPU())
}

// Restore runs pg_restore of dir/dump.pgc into inst.
func Restore(ctx context.Context, inst scratch.Instance, jobs int) *RestoreResult {
	t0 := time.Now()
	stderr, err := inst.Restore(ctx, DumpFile, jobs)
	return &RestoreResult{Duration: time.Since(t0), Errors: dump.RestoreErrors(stderr), Err: err}
}

// Session is a scratch database restored from a stored dump. Close destroys
// it and the work dir; it is safe to call more than once.
type Session struct {
	Instance scratch.Instance
	Dir      string
	Restore  *RestoreResult
	log      *slog.Logger
	closed   bool
}

// Open fetches obj, starts a scratch instance of the given major and restores
// into it. Any problem (checksum, decrypt, start, pg_restore errors) is an error.
// noTmpfs keeps the scratch data on disk (for masking, which rewrites tables).
func Open(ctx context.Context, store *storage.Store, obj Object, ids []age.Identity,
	rt scratch.Runtime, runID, database string, major, jobs int, noTmpfs bool, log *slog.Logger) (*Session, error) {

	dir, err := os.MkdirTemp("", "pgsafe-scratch-")
	if err != nil {
		return nil, err
	}
	s := &Session{Dir: dir, log: log}
	if _, err := Fetch(ctx, store, obj, ids, dir); err != nil {
		s.Close(ctx)
		return nil, err
	}
	inst, err := rt.Start(ctx, scratch.StartOptions{RunID: runID, Database: database, Major: major, WorkDir: dir, DumpBytes: obj.SizeBytes, NoTmpfs: noTmpfs})
	if err != nil {
		s.Close(ctx)
		return nil, fmt.Errorf("start scratch: %w", err)
	}
	s.Instance = inst
	log.Info("restoring into scratch", "scratch", inst.Describe())
	s.Restore = Restore(ctx, inst, jobs)
	if ctx.Err() != nil {
		s.Close(ctx)
		return nil, ctx.Err()
	}
	if !s.Restore.OK() {
		s.Close(ctx)
		return nil, fmt.Errorf("restore failed: %s", s.Restore.Detail())
	}
	return s, nil
}

// Close destroys the scratch instance and removes the work dir, even if ctx
// is already cancelled.
func (s *Session) Close(ctx context.Context) {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	if s.Instance != nil {
		dctx, cancel := scratch.DestroyContext(ctx)
		defer cancel()
		if err := s.Instance.Destroy(dctx); err != nil && s.log != nil {
			s.log.Error("scratch cleanup failed", "scratch", s.Instance.Describe(), "err", err)
		}
	}
	_ = os.RemoveAll(s.Dir)
}

func download(ctx context.Context, store *storage.Store, key, dst string) (int64, string, error) {
	rc, _, err := store.Get(ctx, key)
	if err != nil {
		return 0, "", err
	}
	defer rc.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", err
	}
	h := crypto.NewHasher()
	if _, err := io.Copy(io.MultiWriter(f, h), rc); err != nil {
		f.Close()
		return 0, "", fmt.Errorf("download %s: %w", key, err)
	}
	if err := f.Close(); err != nil {
		return 0, "", err
	}
	return h.Size(), h.Sum(), nil
}

func decryptFile(src, dst string, ids []age.Identity) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	r, err := crypto.Decrypt(in, ids)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return fmt.Errorf("age decrypt: %w", err)
	}
	return out.Close()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
