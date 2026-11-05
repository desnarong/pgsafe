package main

import (
	"context"
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/ops"
)

type verifyOutput struct {
	Database string                 `json:"database"`
	Status   string                 `json:"status"`
	Report   *manifest.VerifyReport `json:"report,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

func newVerifyCmd(a *app) *cobra.Command {
	var dbName, backupID string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Restore a backup into a scratch database and check it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			if backupID != "" && dbName == "" {
				if len(cfg.Databases) != 1 {
					return exitcode.Config(errors.New("--backup needs --db when the config has several databases"))
				}
				dbName = cfg.Databases[0].Name
			}
			env, dbs, err := a.envFor(ctx, cfg, dbName, false, true)
			if err != nil {
				return err
			}
			var results []verifyOutput
			worst := exitcode.OK
			for _, db := range dbs {
				o := env.Verify(ctx, db, backupID)
				results = append(results, a.printVerify(o))
				worst = max(worst, o.Code())
			}
			if a.g.json {
				if err := a.printJSON(map[string]any{"verifications": results}); err != nil {
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
	cmd.Flags().StringVar(&backupID, "backup", "", "backup ID to verify (default: newest)")
	return cmd
}

func (a *app) printVerify(o *ops.Outcome) verifyOutput {
	out := verifyOutput{Database: o.Database, Status: o.Status, Report: o.Verify}
	if o.Verify == nil {
		out.Error = o.Error
		a.printf("✗ %s: verify could not run: %s\n", o.Database, o.Error)
		return out
	}
	if o.Verify.Status == manifest.StatusError {
		out.Error = o.Error
	}
	a.printReport(o.Database, o.Verify)
	return out
}

// env loads the config and builds the operation environment for the selected
// databases. needDBURLs checks the env vars of their URLs; needRuntime builds
// the scratch runtime.
func (a *app) env(ctx context.Context, dbName string, needDBURLs, needRuntime bool) (*ops.Env, []config.Database, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, nil, err
	}
	return a.envFor(ctx, cfg, dbName, needDBURLs, needRuntime)
}

func (a *app) envFor(ctx context.Context, cfg *config.Config, dbName string, needDBURLs, needRuntime bool) (*ops.Env, []config.Database, error) {
	dbs, err := cfg.Select(dbName)
	if err != nil {
		return nil, nil, exitcode.Config(err)
	}
	if needDBURLs {
		if err := requireDatabases(cfg, dbs); err != nil {
			return nil, nil, err
		}
	}
	env := &ops.Env{Config: cfg, Logger: a.logger(), AgentVersion: version}
	a.cloud = a.attachCloud(cfg, env)
	if needRuntime {
		if env.Runtime, err = ops.NewRuntime(cfg); err != nil {
			return nil, nil, err
		}
	}
	if env.Store, err = a.store(ctx, cfg); err != nil {
		return nil, nil, err
	}
	return env, dbs, nil
}

func (a *app) printReport(db string, r *manifest.VerifyReport) {
	if a.g.json {
		return
	}
	mark := map[string]string{manifest.StatusPassed: "✓", manifest.StatusFailed: "✗", manifest.StatusError: "✗", manifest.StatusSkip: "-"}
	rto := time.Duration(r.RestoreDurationMS) * time.Millisecond
	switch r.Status {
	case manifest.StatusPassed:
		a.printf("✓ %s: backup %s restores — restore took %s, %d/%d tables OK\n", db, r.BackupID, rto.Round(time.Millisecond), r.TablesOK, r.TablesTotal)
	case manifest.StatusError:
		a.printf("✗ %s: backup %s could not be verified: %s\n", db, r.BackupID, r.Error)
	default:
		a.printf("✗ %s: backup %s FAILED verification\n", db, r.BackupID)
	}
	for _, c := range r.Checks {
		a.printf("    %s %-16s %s\n", mark[c.Status], c.Name, c.Detail)
	}
}
