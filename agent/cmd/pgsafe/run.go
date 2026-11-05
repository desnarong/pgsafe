package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/cleanup"
	"github.com/desnarong/pgsafe/agent/internal/cloud"
	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/lock"
	"github.com/desnarong/pgsafe/agent/internal/notify"
	"github.com/desnarong/pgsafe/agent/internal/ops"
	"github.com/desnarong/pgsafe/agent/internal/scheduler"
	"github.com/desnarong/pgsafe/shared/apitypes"
)

func newRunCmd(a *app) *cobra.Command {
	var (
		once, printSchedule, noCatchUp bool
		stopAfter                      time.Duration
		maxConcurrent                  int
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run as a daemon: backup, verify and stage on the configured schedule",
		Long: `run schedules every database per schedule: in pgsafe.yaml. A backup is
followed by verify (verify: after_backup) and, only if verify passed, by stage
(stage: after_verify). Results go to the run log and to notify: webhooks.

On start it removes leftovers of interrupted runs and runs a missed backup
(e.g. the machine was off at 02:00). SIGINT/SIGTERM stop it gracefully.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			jobs, planErr := scheduler.Plan(cfg)
			if printSchedule {
				if planErr != nil {
					return exitcode.Config(planErr)
				}
				up := scheduler.Upcoming(jobs, time.Now(), 3)
				keys := make([]string, 0, len(up))
				for k := range up {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				if a.g.json {
					return a.printJSON(up)
				}
				for _, k := range keys {
					a.printf("%s\n", k)
					for _, t := range up[k] {
						a.printf("    %s\n", t.Local().Format("2006-01-02 15:04:05 Mon"))
					}
				}
				return nil
			}
			if planErr != nil && !once {
				return exitcode.Config(planErr)
			}
			if err := requireDatabases(cfg, cfg.Databases); err != nil {
				return err
			}

			unlock, err := lock.Daemon(cfg.Resolve(cfg.StateDir))
			if err != nil {
				return err
			}
			defer unlock()

			log := a.logger()
			rep := cleanup.All(ctx, cfg)
			for _, r := range rep.Removed() {
				log.Warn("removed leftover from an interrupted run", "item", r)
			}

			env, _, err := a.envFor(ctx, cfg, "", false, true)
			if err != nil {
				return err
			}
			d := &scheduler.Daemon{
				Config: cfg, Runner: scheduler.EnvRunner{Env: env}, Notifier: notify.New(cfg.Notify, log), Logger: log,
				MaxConcurrent: maxConcurrent, AgentVersion: version,
				LatestBackup: func(ctx context.Context, db string) (*time.Time, error) {
					list, err := env.Store.ListBackups(ctx, db, false)
					if err != nil || len(list) == 0 {
						return nil, err
					}
					t := list[0].Manifest.CreatedAt
					return &t, nil
				},
			}

			if a.cloud != nil {
				rep, _ := env.Reporter.(*cloud.Reporter)
				d.Cloud = &cloudLink{c: a.cloud, cfg: cfg, rep: rep}
			}

			if once {
				outcomes := d.RunOnce(ctx)
				worst := exitcode.OK
				for _, o := range outcomes {
					worst = max(worst, o.Code())
					mark := "✓"
					if o.Status != ops.StatusPassed {
						mark = "✗"
					}
					detail := o.Summary
					if o.Error != "" {
						detail = o.Error
					}
					a.printf("%s %-6s %-8s %-8s %s\n", mark, o.Kind, o.Database, o.Status, detail)
				}
				if a.g.json {
					if err := a.printJSON(map[string]any{"runs": outcomes}); err != nil {
						return err
					}
				}
				if worst != exitcode.OK {
					return exitcode.Reported(worst)
				}
				return nil
			}

			if stopAfter > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, stopAfter)
				defer cancel()
			}
			if err := d.Run(ctx, jobs, !noCatchUp); err != nil {
				return fmt.Errorf("daemon: %w", err)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&once, "once", false, "run backup → verify → stage for every database once, then exit")
	f.BoolVar(&printSchedule, "print-schedule", false, "print the next run times and exit")
	f.BoolVar(&noCatchUp, "no-catch-up", false, "do not run a missed backup at start")
	f.DurationVar(&stopAfter, "stop-after", 0, "stop gracefully after this long (e.g. 2h; 0 = run until signalled)")
	f.IntVar(&maxConcurrent, "max-concurrent", 1, "databases processed at the same time")
	return cmd
}

// cloudLink connects the daemon to the control plane.
type cloudLink struct {
	c   *cloud.Client
	cfg *config.Config
	rep *cloud.Reporter
}

func (l *cloudLink) Heartbeat(ctx context.Context) (int64, error) {
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := l.c.Heartbeat(hctx, cloud.Hello(l.cfg, version))
	if l.rep != nil {
		l.rep.Flush() // deliver reports queued while the control plane was unreachable
	}
	if err != nil {
		return 0, err
	}
	return resp.ConfigVersion, nil
}

func (l *cloudLink) Commands(ctx context.Context, wait time.Duration) ([]apitypes.Command, error) {
	return l.c.Commands(ctx, wait)
}

func (l *cloudLink) CommandDone(ctx context.Context, id string, res apitypes.CommandResult) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res.Error = cloud.SafeText(res.Error)
	return l.c.CommandDone(cctx, id, res)
}

func (l *cloudLink) Sync(ctx context.Context) (map[string]config.Schedule, error) {
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := cloud.Sync(sctx, l.c, l.cfg)
	if err != nil {
		return nil, err
	}
	return res.Managed, nil
}
