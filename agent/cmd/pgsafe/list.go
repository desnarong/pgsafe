package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/runlog"
)

func newListCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List backups or runs",
	}
	cmd.AddCommand(newListBackupsCmd(a), newListRunsCmd(a))
	return cmd
}

type backupRow struct {
	Database          string    `json:"database"`
	BackupID          string    `json:"backup_id"`
	CreatedAt         time.Time `json:"created_at"`
	SizeBytes         int64     `json:"size_bytes"`
	Tables            int       `json:"tables"`
	PGServerVersion   string    `json:"pg_server_version"`
	Encryption        string    `json:"encryption"`
	VerifiedStatus    string    `json:"verified_status"` // passed | failed | error | "" (never)
	VerifiedAt        time.Time `json:"verified_at,omitzero"`
	RestoreDurationMS int64     `json:"restore_duration_ms,omitempty"`
}

func newListBackupsCmd(a *app) *cobra.Command {
	var dbName string
	cmd := &cobra.Command{
		Use:   "backups",
		Short: "List complete backups and their verify status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			dbs, err := cfg.Select(dbName)
			if err != nil {
				return exitcode.Config(err)
			}
			store, err := a.store(ctx, cfg)
			if err != nil {
				return err
			}
			rows := []backupRow{}
			for _, db := range dbs {
				list, err := store.ListBackups(ctx, db.Name, true)
				if err != nil {
					return err
				}
				for _, e := range list {
					m := e.Manifest
					r := backupRow{Database: db.Name, BackupID: m.BackupID, CreatedAt: m.CreatedAt, SizeBytes: m.SizeBytes,
						Tables: len(m.Tables), PGServerVersion: m.PGServerVersion, Encryption: m.Encryption}
					if e.Verify != nil {
						r.VerifiedStatus, r.VerifiedAt, r.RestoreDurationMS = e.Verify.Status, e.Verify.FinishedAt, e.Verify.RestoreDurationMS
					}
					rows = append(rows, r)
				}
			}
			if a.g.json {
				return a.printJSON(map[string]any{"backups": rows})
			}
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "DATABASE\tBACKUP\tCREATED\tSIZE\tTABLES\tPG\tVERIFIED\tRESTORE")
			for _, r := range rows {
				ver, rto := "never", "-"
				if r.VerifiedStatus != "" {
					ver = r.VerifiedStatus
				}
				if r.RestoreDurationMS > 0 {
					rto = (time.Duration(r.RestoreDurationMS) * time.Millisecond).Round(time.Second).String()
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", r.Database, r.BackupID,
					r.CreatedAt.Local().Format("2006-01-02 15:04"), humanBytes(r.SizeBytes), r.Tables, r.PGServerVersion, ver, rto)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&dbName, "db", "", "only this database")
	return cmd
}

func newListRunsCmd(a *app) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "runs",
		Short: "List recent runs recorded on this machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			runs, err := runlog.Read(cfg.Resolve(cfg.StateDir), limit)
			if err != nil {
				return err
			}
			if runs == nil {
				runs = []runlog.Run{}
			}
			if a.g.json {
				return a.printJSON(map[string]any{"runs": runs})
			}
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "RUN\tKIND\tDATABASE\tSTATUS\tSTARTED\tDURATION\tDETAIL")
			for _, r := range runs {
				detail := r.Summary
				if r.Status != manifest.StatusPassed && r.Error != "" {
					detail = r.Error
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Kind, r.Database, r.Status,
					r.StartedAt.Local().Format("2006-01-02 15:04:05"), (time.Duration(r.DurationMS) * time.Millisecond).Round(time.Millisecond), detail)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "max runs to show (0 = all)")
	return cmd
}
