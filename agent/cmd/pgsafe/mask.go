package main

import (
	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/maskrun"
	"github.com/desnarong/pgsafe/agent/internal/ops"
)

type maskOutput struct {
	Database string          `json:"database"`
	Status   string          `json:"status"` // passed | blocked | failed
	Result   *maskrun.Result `json:"result,omitempty"`
	Error    string          `json:"error,omitempty"`
}

func newMaskCmd(a *app) *cobra.Command {
	var dbName, backupID string
	cmd := &cobra.Command{
		Use:   "mask",
		Short: "Restore a backup, mask it with pgsafe.masking.yaml and publish a masked dump",
		Long: `mask restores a backup into a scratch database, refuses to continue if any
likely-PII column is unreviewed (exit 3), masks everything in SQL, re-checks the
result and uploads the masked dump to masked/ in storage.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			env, dbs, err := a.env(ctx, dbName, false, true)
			if err != nil {
				return err
			}
			a.syncRules(ctx, env.Config, a.cloud)
			var outs []maskOutput
			worst := exitcode.OK
			for _, db := range dbs {
				o := env.Mask(ctx, db.Name, backupID)
				outs = append(outs, a.printMask(o))
				worst = max(worst, o.Code())
			}
			if a.g.json {
				if err := a.printJSON(map[string]any{"masks": outs}); err != nil {
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
	cmd.Flags().StringVar(&backupID, "backup", "", "backup to mask (default: newest)")
	return cmd
}

// printMask prints a mask outcome (also used when stage re-masks).
func (a *app) printMask(o *ops.Outcome) maskOutput {
	out := maskOutput{Database: o.Database, Status: o.Status, Result: o.Mask, Error: o.Error}
	switch {
	case o.Status == ops.StatusBlocked:
		a.printf("✗ %s: %s\n", o.Database, o.Error)
		if o.Mask != nil && len(o.Mask.RulesAdded) > 0 {
			a.printf("  added %d suggestion(s) to the masking rules for review\n", len(o.Mask.RulesAdded))
		}
	case o.Status != ops.StatusPassed:
		a.printf("✗ %s: mask failed: %s\n", o.Database, o.Error)
	default:
		res := o.Mask
		m := res.Masked
		a.printf("✓ %s: masked dump %s from backup %s  %s\n", o.Database, m.BackupID, m.SourceBackupID, humanBytes(m.SizeBytes))
		for _, t := range res.Report.Tables {
			a.printf("    %-28s %-8s %8d rows  %v\n", t.Table, t.Path, t.Rows, t.Columns)
		}
		for _, c := range res.Report.PostChecks {
			a.printf("    ✓ %-16s %s\n", c.Name, c.Detail)
		}
		for _, w := range res.Report.Decision.AutoApplied {
			a.printf("    ⚠ applied without review: %s\n", w)
		}
		for _, w := range res.Report.Decision.Warnings {
			a.printf("    ⚠ %s\n", w)
		}
		if n := len(res.Report.Decision.Stale); n > 0 {
			a.printf("    ⚠ %d rule(s) for columns that no longer exist: %v\n", n, res.Report.Decision.Stale)
		}
	}
	return out
}
