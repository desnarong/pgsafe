package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ops"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/redact"
	"github.com/desnarong/pgsafe/agent/internal/restore"
	"github.com/desnarong/pgsafe/agent/internal/stage"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

func newPullCmd(a *app) *cobra.Command {
	var dbName, to, maskedID string
	var staging, replace bool
	cmd := &cobra.Command{
		Use:   "pull --staging --to URL",
		Short: "Restore the newest masked dump into a local database (for developers)",
		Long: `pull downloads the newest masked dump of a database and restores it into --to.
It needs only storage access and the staging key — no production credentials.
The target database is created; with --replace an existing one is swapped out.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if !staging {
				return exitcode.Config(errors.New("only masked data can be pulled: pass --staging"))
			}
			if to == "" {
				return exitcode.Config(errors.New("--to is required, e.g. --to postgres://localhost/app_dev"))
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			if dbName == "" {
				if len(cfg.Databases) != 1 {
					return exitcode.Config(errors.New("--db is required when the config has several databases"))
				}
				dbName = cfg.Databases[0].Name
			}
			if _, err := cfg.Database(dbName); err != nil {
				return exitcode.Config(err)
			}
			target, err := pg.ParseURL(to)
			if err != nil {
				return exitcode.Config(fmt.Errorf("--to: %w", err))
			}
			if err := ops.RefuseSource(cfg, target); err != nil {
				return err
			}
			store, err := a.store(ctx, cfg)
			if err != nil {
				return err
			}
			m, err := store.FindMasked(ctx, dbName, maskedID)
			if err != nil {
				return err
			}
			idents, err := ops.StagingIdentities(cfg, m)
			if err != nil {
				return err
			}
			dir, err := os.MkdirTemp("", "pgsafe-pull-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			fr, err := restore.Fetch(ctx, store, restore.Object{Key: storage.MaskedKey(m.Database, m.BackupID, m.Object),
				SHA256: m.SHA256, SizeBytes: m.SizeBytes, Encrypted: m.Encryption == "age"}, idents, dir)
			if err != nil {
				return err
			}
			res, err := stage.Replace(ctx, stage.Options{Target: target, DumpPath: fr.DumpPath, PGClient: cfg.PGClient,
				DockerImage: cfg.Verify.DockerImage, Jobs: cfg.Verify.Jobs, MustNotExist: !replace, Logger: a.logger()})
			if errors.Is(err, stage.ErrExists) {
				return exitcode.Config(err)
			}
			if err != nil {
				return err
			}
			if a.g.json {
				return a.printJSON(map[string]any{"database": dbName, "masked_id": m.BackupID,
					"source_backup_id": m.SourceBackupID, "to": redact.URL(to), "result": res})
			}
			a.printf("✓ restored masked dump %s (from backup %s, %s) into %s in %s\n", m.BackupID, m.SourceBackupID,
				m.CreatedAt.Local().Format("2006-01-02 15:04"), redact.URL(to), time.Duration(res.DurationMS)*time.Millisecond)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&staging, "staging", false, "pull masked staging data (required)")
	f.StringVar(&dbName, "db", "", "database name from pgsafe.yaml")
	f.StringVar(&to, "to", "", "target database URL (created; must not be a source database)")
	f.BoolVar(&replace, "replace", false, "replace the target database if it exists")
	f.StringVar(&maskedID, "masked", "", "masked dump ID (default: newest)")
	return cmd
}
