package main

import (
	"fmt"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/mask"
	"github.com/desnarong/pgsafe/agent/internal/ops"
	"github.com/desnarong/pgsafe/agent/internal/runlog"
	"github.com/desnarong/pgsafe/agent/internal/scan"
)

type scanOutput struct {
	Database  string            `json:"database"`
	Source    string            `json:"source"` // scratch | source
	BackupID  string            `json:"backup_id,omitempty"`
	Tables    int               `json:"tables"`
	Columns   int               `json:"columns"`
	Findings  []scan.Finding    `json:"findings"`
	RulesFile string            `json:"rules_file"`
	Rules     *mask.MergeResult `json:"rules,omitempty"`
}

func newScanCmd(a *app) *cobra.Command {
	var dbName, backupID string
	var source, noWrite bool
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Find PII columns and add unreviewed masking rules for them",
		Long: `scan restores the newest backup into a scratch database (or, with --source,
samples the live database read-only), classifies every column and adds rules for
likely PII to pgsafe.masking.yaml with reviewed: false. Reviewed rules are never changed.
Only table/column names and detector results are kept — never data values.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			env, dbs, err := a.env(ctx, dbName, false, true)
			if err != nil {
				return err
			}
			var outs []scanOutput
			for _, db := range dbs {
				o := env.Scan(ctx, db, ops.ScanOptions{BackupID: backupID, Source: source, NoWrite: noWrite})
				if o.Status != ops.StatusPassed {
					return exitcode.Reported(a.printFailed("scan", o))
				}
				r := o.Scan
				out := scanOutput{Database: db.Name, Source: r.Source, BackupID: r.BackupID, Tables: r.Tables, Columns: r.Columns,
					Findings: r.Findings, RulesFile: r.RulesFile, Rules: r.Rules}
				outs = append(outs, out)
				a.printScan(out)
			}
			if a.g.json {
				return a.printJSON(map[string]any{"scans": outs})
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dbName, "db", "", "only this database (default: all)")
	f.StringVar(&backupID, "backup", "", "backup to scan (default: newest)")
	f.BoolVar(&source, "source", false, "sample the live database read-only instead of a restored backup")
	f.BoolVar(&noWrite, "no-write", false, "report findings without updating the rules file")
	return cmd
}

// printFailed reports a failed outcome and returns its exit code.
func (a *app) printFailed(what string, o *ops.Outcome) int {
	if a.g.json {
		_ = a.printJSON(map[string]any{"error": o.Error, "status": o.Status, "database": o.Database})
	} else {
		a.printf("✗ %s: %s failed: %s\n", o.Database, what, o.Error)
	}
	return o.Code()
}

func (a *app) printScan(o scanOutput) {
	if a.g.json {
		return
	}
	src := "backup " + o.BackupID
	if o.Source == "source" {
		src = "live database (read-only sample)"
	}
	a.printf("%s: scanned %d columns in %d tables of %s\n", o.Database, o.Columns, o.Tables, src)
	tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  COLUMN\tDETECTOR\tCONFIDENCE\tSUGGESTED\tREASON")
	for _, f := range o.Findings {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", f.Key(), f.Detector, f.Confidence, f.Strategy, f.Reason)
	}
	tw.Flush()
	if r := o.Rules; r != nil {
		a.printf("%s: %d added, %d updated (unreviewed), %d reviewed kept", o.RulesFile, len(r.Added), len(r.Updated), len(r.Kept))
		if len(r.Stale) > 0 {
			a.printf(", %d stale: %v", len(r.Stale), r.Stale)
		}
		a.printf("\n")
		if len(r.Added)+len(r.Updated) > 0 {
			a.printf("next: review %s, set reviewed: true (strategy: keep for non-PII), then run pgsafe mask\n", o.RulesFile)
		}
	}
}

func appendRun(cfg *config.Config, r runlog.Run, log *slog.Logger) {
	r.FinishedAt = time.Now().UTC()
	r.DurationMS = r.FinishedAt.Sub(r.StartedAt).Milliseconds()
	if err := runlog.Append(cfg.Resolve(cfg.StateDir), r); err != nil {
		log.Warn("could not write run log", "err", err)
	}
}
