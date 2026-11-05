package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/ops"
)

type backupOutput struct {
	Database string             `json:"database"`
	Status   string             `json:"status"`
	RunID    string             `json:"run_id"`
	BackupID string             `json:"backup_id,omitempty"`
	Manifest *manifest.Manifest `json:"manifest,omitempty"`
	Removed  []string           `json:"removed_by_retention,omitempty"`
	Error    string             `json:"error,omitempty"`
}

func newBackupCmd(a *app) *cobra.Command {
	var dbName string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Dump, encrypt and upload a backup with its manifest",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			env, dbs, err := a.env(ctx, dbName, true, false)
			if err != nil {
				return err
			}
			var results []backupOutput
			worst := exitcode.OK
			for _, db := range dbs {
				o := env.Backup(ctx, db)
				results = append(results, a.printBackup(o))
				worst = max(worst, o.Code())
			}
			if a.g.json {
				if err := a.printJSON(map[string]any{"backups": results}); err != nil {
					return err
				}
			}
			if worst != exitcode.OK {
				return exitcode.Reported(worst)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbName, "db", "", "only this database (default: all)")
	return cmd
}

func (a *app) printBackup(o *ops.Outcome) backupOutput {
	out := backupOutput{Database: o.Database, RunID: o.RunID, Status: o.Status, Error: o.Error}
	if o.Status != ops.StatusPassed {
		a.printf("✗ %s: backup failed: %s\n", o.Database, o.Error)
		return out
	}
	res := o.Backup
	m := res.Manifest
	out.BackupID, out.Manifest, out.Removed = m.BackupID, m, res.Removed
	a.printf("✓ %s: %s  %s  %d tables  %s  (pg %s, encryption %s)\n", o.Database, m.BackupID,
		humanBytes(m.SizeBytes), len(m.Tables), time.Duration(m.DurationMS)*time.Millisecond, m.PGServerVersion, m.Encryption)
	if len(res.Removed) > 0 {
		a.printf("  retention removed %d old backup(s)\n", len(res.Removed))
	}
	if res.RetentionError != "" {
		a.printf("  ⚠ retention: %s\n", res.RetentionError)
	}
	return out
}
