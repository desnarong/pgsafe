package storage

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/desnarong/pgsafe/agent/internal/manifest"
)

// Object layout (relative to storage.prefix):
//
//	backups/<db>/<backup_id>/dump.pgc.age   (or dump.pgc when unencrypted)
//	backups/<db>/<backup_id>/manifest.json  written last: its presence marks a complete backup
//	backups/<db>/<backup_id>/verify.json    latest verify result (metadata only)

//	masked/<db>/<masked_id>/{dump.pgc[.age], manifest.json, mask.json}   masked dumps (Phase 2)

// Roots of the two kinds of dumps.
const (
	BackupsRoot = "backups/"
	MaskedRoot  = "masked/"
)

func DatabaseDir(db string) string         { return BackupsRoot + db + "/" }
func BackupDir(db, id string) string       { return DatabaseDir(db) + id + "/" }
func ObjectKey(db, id, name string) string { return BackupDir(db, id) + name }

func MaskedKey(db, id, name string) string { return MaskedRoot + db + "/" + id + "/" + name }

// BackupEntry is a complete backup found in storage.
type BackupEntry struct {
	Manifest *manifest.Manifest
	Verify   *manifest.VerifyReport // nil if never verified
	Keys     []string               // every object under the backup dir
}

// ListBackups returns complete backups of db (those with a manifest),
// newest first. Directories without a manifest (failed uploads) are ignored.
func (s *Store) ListBackups(ctx context.Context, db string, withVerify bool) ([]BackupEntry, error) {
	return s.listEntries(ctx, BackupsRoot, db, withVerify)
}

// ListMasked returns complete masked dumps of db, newest first.
func (s *Store) ListMasked(ctx context.Context, db string) ([]BackupEntry, error) {
	return s.listEntries(ctx, MaskedRoot, db, false)
}

func (s *Store) listEntries(ctx context.Context, root, db string, withVerify bool) ([]BackupEntry, error) {
	dbDir := root + db + "/"
	keys, err := s.List(ctx, dbDir)
	if err != nil {
		return nil, err
	}
	byID := map[string][]string{}
	hasManifest := map[string]bool{}
	hasVerify := map[string]bool{}
	for _, k := range keys {
		rest := strings.TrimPrefix(k, dbDir)
		id, name, ok := strings.Cut(rest, "/")
		if !ok || strings.Contains(name, "/") {
			continue
		}
		byID[id] = append(byID[id], k)
		switch name {
		case manifest.FileName:
			hasManifest[id] = true
		case manifest.VerifyFileName:
			hasVerify[id] = true
		}
	}
	var out []BackupEntry
	for id := range byID {
		if !hasManifest[id] {
			continue
		}
		data, err := s.GetBytes(ctx, dbDir+id+"/"+manifest.FileName)
		if err != nil {
			return nil, err
		}
		m, err := manifest.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", dbDir+id+"/"+manifest.FileName, err)
		}
		e := BackupEntry{Manifest: m, Keys: byID[id]}
		if withVerify && hasVerify[id] {
			if data, err := s.GetBytes(ctx, dbDir+id+"/"+manifest.VerifyFileName); err == nil {
				e.Verify, _ = manifest.ParseVerify(data)
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Manifest, out[j].Manifest
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.After(b.CreatedAt)
		}
		return a.BackupID > b.BackupID
	})
	return out, nil
}

// ErrNoBackups is returned when a database has no complete backup.
var ErrNoBackups = errors.New("no backups found")

// FindBackup returns the backup with id, or the newest one when id is empty.
func (s *Store) FindBackup(ctx context.Context, db, id string) (*manifest.Manifest, error) {
	if id != "" {
		data, err := s.GetBytes(ctx, ObjectKey(db, id, manifest.FileName))
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("backup %s of %s: %w", id, db, ErrNoBackups)
		}
		if err != nil {
			return nil, err
		}
		return manifest.Parse(data)
	}
	list, err := s.ListBackups(ctx, db, false)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("database %s: %w", db, ErrNoBackups)
	}
	return list[0].Manifest, nil
}

// Base returns the last path element of a key.
func Base(key string) string { return path.Base(key) }

// FindMasked returns the masked dump with id, or the newest when id is empty.
func (s *Store) FindMasked(ctx context.Context, db, id string) (*manifest.Manifest, error) {
	if id != "" {
		data, err := s.GetBytes(ctx, MaskedKey(db, id, manifest.FileName))
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("masked dump %s of %s: %w", id, db, ErrNoBackups)
		}
		if err != nil {
			return nil, err
		}
		return manifest.Parse(data)
	}
	list, err := s.ListMasked(ctx, db)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no masked dump of %s (run pgsafe mask): %w", db, ErrNoBackups)
	}
	return list[0].Manifest, nil
}

// WithLocation returns a store on another bucket/prefix with the same client.
func (s *Store) WithLocation(bucket, prefix string) *Store {
	if bucket == "" {
		bucket = s.bucket
	}
	p := strings.TrimLeft(prefix, "/")
	if p != "" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return &Store{client: s.client, bucket: bucket, prefix: p}
}

// Location returns bucket and prefix.
func (s *Store) Location() (string, string) { return s.bucket, s.prefix }
