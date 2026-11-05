// Package backup implements the backup pipeline (design doc §3.3):
// snapshot → schema/row counts → pg_dump | age | sha256 | S3 multipart → manifest → retention.
package backup

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"filippo.io/age"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ids"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/pipeline"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

type Options struct {
	Config       *config.Config
	Database     config.Database
	Store        *storage.Store
	Logger       *slog.Logger
	AgentVersion string
}

type Result struct {
	Manifest       *manifest.Manifest `json:"manifest"`
	Removed        []string           `json:"removed_by_retention"`
	RetentionError string             `json:"retention_error,omitempty"`
}

// Run performs one backup of o.Database.
func Run(ctx context.Context, o Options) (*Result, error) {
	cfg, db, log := o.Config, o.Database, o.Logger
	start := time.Now().UTC()
	id := ids.Backup(start)
	log = log.With("db", db.Name, "backup_id", id)

	ci, err := pg.ParseURL(db.URL)
	if err != nil {
		return nil, exitcode.Config(err)
	}
	exclTables, err := dump.CompilePatterns(db.ExcludeTables)
	if err != nil {
		return nil, exitcode.Config(fmt.Errorf("exclude_tables: %w", err))
	}
	exclData, err := dump.CompilePatterns(db.ExcludeTableData)
	if err != nil {
		return nil, exitcode.Config(fmt.Errorf("exclude_table_data: %w", err))
	}
	var recipients []age.Recipient
	if cfg.Encryption.Type == "age" {
		if recipients, err = crypto.LoadRecipients(cfg.Resolve(cfg.Encryption.RecipientsFile)); err != nil {
			return nil, exitcode.Config(err)
		}
	}

	conn, err := pg.Connect(ctx, ci)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))

	ver, err := pg.ServerVersion(ctx, conn)
	if err != nil {
		return nil, err
	}
	if ver.Major < 14 || ver.Major > 18 {
		log.Warn("PostgreSQL version is outside the supported range 14–18", "version", ver.String)
	}
	client, err := dump.Resolve(ctx, cfg.PGClient, ver.Major, cfg.Verify.DockerImage)
	if err != nil {
		return nil, err
	}
	log.Info("backup started", "pg_version", ver.String, "pg_dump", client.Version, "client", client.Mode)

	// Everything below reads the same snapshot pg_dump will dump, so the
	// manifest's row counts match the archive exactly.
	snap, err := pg.ExportSnapshot(ctx, conn)
	if err != nil {
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			_ = snap.Tx.Rollback(context.WithoutCancel(ctx))
		}
	}()

	tables, err := pg.ListTables(ctx, snap.Tx)
	if err != nil {
		return nil, err
	}
	var included []pg.Table
	var mtables []manifest.Table
	var args []string
	for _, t := range tables {
		if dump.MatchAny(exclTables, t) {
			args = append(args, "--exclude-table="+dump.TableArg(t))
			continue
		}
		included = append(included, t)
		mt := manifest.Table{Schema: t.Schema, Name: t.Name}
		if dump.MatchAny(exclData, t) {
			args = append(args, "--exclude-table-data="+dump.TableArg(t))
			mt.DataExcluded, mt.RowsExact = true, true
		} else if mt.Rows, mt.RowsExact, err = pg.CountRows(ctx, snap.Tx, t, cfg.Verify.RowCount.ExactBelowRows); err != nil {
			return nil, err
		}
		mtables = append(mtables, mt)
	}
	schemas, err := pg.ReadSchema(ctx, snap.Tx, included)
	if err != nil {
		return nil, err
	}
	args = append(args, "--snapshot="+snap.ID)

	objName := "dump.pgc"
	encName := "none"
	if recipients != nil {
		objName, encName = "dump.pgc.age", "age"
	}
	key := storage.ObjectKey(db.Name, id, objName)
	size, sum, err := pipeline.StreamUpload(ctx,
		func(ctx context.Context) *exec.Cmd { return client.DumpCommand(ctx, ci, args) },
		func(s string) string { return dump.Scrub(s, ci) },
		recipients, o.Store, key)
	if err != nil {
		return nil, err
	}
	if err := snap.Release(ctx); err != nil {
		return nil, fmt.Errorf("release snapshot: %w", err)
	}
	released = true

	finished := time.Now().UTC()
	m := &manifest.Manifest{
		BackupID:         id,
		Database:         db.Name,
		CreatedAt:        start,
		FinishedAt:       finished,
		DurationMS:       finished.Sub(start).Milliseconds(),
		PGServerVersion:  ver.String,
		PGServerMajor:    ver.Major,
		PGDumpVersion:    client.Version,
		Format:           manifest.FormatCustom,
		Encryption:       encName,
		Object:           objName,
		SizeBytes:        size,
		SHA256:           sum,
		SchemaHash:       pg.HashSchema(schemas),
		Tables:           mtables,
		ExcludeTables:    db.ExcludeTables,
		ExcludeTableData: db.ExcludeTableData,
		AgentVersion:     o.AgentVersion,
	}
	data, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	// The manifest is written last: its presence marks the backup complete.
	if err := o.Store.PutBytes(ctx, storage.ObjectKey(db.Name, id, manifest.FileName), data, "application/json"); err != nil {
		_ = o.Store.Delete(context.WithoutCancel(ctx), key)
		return nil, err
	}
	log.Info("backup uploaded", "bytes", size, "tables", len(mtables), "duration_ms", m.DurationMS)

	res := &Result{Manifest: m, Removed: []string{}}
	removed, err := applyRetention(ctx, o.Store, db.Name, cfg.Retention)
	if err != nil {
		// Retention problems never fail a successful backup.
		log.Warn("retention failed", "err", err)
		res.RetentionError = err.Error()
	}
	if removed != nil {
		res.Removed = removed
	}
	return res, nil
}

func applyRetention(ctx context.Context, store *storage.Store, db string, r config.Retention) ([]string, error) {
	list, err := store.ListBackups(ctx, db, false)
	if err != nil {
		return nil, err
	}
	items := make([]storage.RetentionItem, len(list))
	byID := map[string]storage.BackupEntry{}
	for i, e := range list {
		items[i] = storage.RetentionItem{ID: e.Manifest.BackupID, CreatedAt: e.Manifest.CreatedAt}
		byID[e.Manifest.BackupID] = e
	}
	_, remove := storage.ApplyRetention(items, r)
	var removed []string
	for _, it := range remove {
		// Only directories with a pgsafe manifest are ever deleted.
		if err := store.Delete(ctx, byID[it.ID].Keys...); err != nil {
			return removed, err
		}
		removed = append(removed, it.ID)
	}
	return removed, nil
}
