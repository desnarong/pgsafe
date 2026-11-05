// Package pipeline streams a pg_dump process through optional age encryption
// and sha256 straight into S3 — nothing is buffered on disk or fully in memory.
package pipeline

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"filippo.io/age"

	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

// StreamUpload runs the command built by newCmd (which must write a dump to
// stdout), encrypts it when recipients is non-nil, and uploads it to key.
// scrub removes credentials from the command's stderr before it appears in errors.
// It returns the size and sha256 of the stored object.
func StreamUpload(ctx context.Context, newCmd func(context.Context) *exec.Cmd, scrub func(string) string,
	recipients []age.Recipient, store *storage.Store, key string) (int64, string, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := newCmd(ctx)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, "", err
	}
	stderr := &dump.TailBuffer{Max: 64 << 10}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return 0, "", fmt.Errorf("start pg_dump: %w", err)
	}

	pr, pw := io.Pipe()
	hasher := crypto.NewHasher()
	sink := io.MultiWriter(pw, hasher)
	done := make(chan error, 1)
	go func() {
		var w io.WriteCloser = nopWriteCloser{sink}
		var err error
		if recipients != nil {
			w, err = crypto.Encrypt(sink, recipients)
		}
		if err == nil {
			_, err = io.Copy(w, stdout)
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			cancel() // stop pg_dump if its output cannot be consumed
		}
		if werr := cmd.Wait(); werr != nil && ctx.Err() == nil {
			err = fmt.Errorf("pg_dump failed (%v): %s", werr, scrub(LastLines(stderr.String(), 5)))
		} else if werr != nil && err == nil {
			err = fmt.Errorf("pg_dump interrupted: %w", werr)
		}
		pw.CloseWithError(err) // nil → clean EOF for the uploader
		done <- err
	}()

	upErr := store.Upload(ctx, key, pr)
	if upErr != nil {
		cancel()
		pr.CloseWithError(upErr)
	}
	dumpErr := <-done
	if dumpErr != nil {
		return 0, "", dumpErr
	}
	if upErr != nil {
		return 0, "", upErr
	}
	return hasher.Size(), hasher.Sum(), nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// LastLines returns the last n non-empty lines of s joined by " | ".
func LastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
