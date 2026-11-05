package main

import (
	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/cleanup"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/lock"
)

func newCleanupCmd(a *app) *cobra.Command {
	var dbName string
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove scratch containers and temporary databases left by interrupted runs",
		Long: `cleanup removes leftovers of runs that died (killed, crashed, rebooted):
scratch containers, pgsafe_verify_* databases on verify.server_url, half-built
staging databases and pgsafe-* temp dirs older than a day. A database whose run
lock is held by a live run is skipped. pgsafe run, verify, scan, mask and stage
also do this automatically for their database.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			var rep *cleanup.Report
			if dbName != "" {
				if _, err := cfg.Database(dbName); err != nil {
					return exitcode.Config(err)
				}
				unlock, err := lock.Database(cfg.Resolve(cfg.StateDir), dbName)
				if err != nil {
					return err
				}
				rep = cleanup.Database(ctx, cfg, dbName)
				unlock()
			} else {
				rep = cleanup.All(ctx, cfg)
			}
			if a.g.json {
				return a.printJSON(rep)
			}
			removed := rep.Removed()
			if len(removed) == 0 {
				a.printf("nothing to clean up\n")
			}
			for _, r := range removed {
				a.printf("removed %s\n", r)
			}
			for _, s := range rep.Skipped {
				a.printf("skipped %s: a run is in progress\n", s)
			}
			for _, e := range rep.Errors {
				a.printf("⚠ %s\n", e)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbName, "db", "", "only this database (default: all)")
	return cmd
}
