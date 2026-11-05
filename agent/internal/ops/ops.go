// Package ops runs one operation on one database — backup, verify, mask,
// stage — with the per-database lock, orphan cleanup and run log. The CLI
// commands and the daemon (pgsafe run) share it.
package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/backup"
	"github.com/desnarong/pgsafe/agent/internal/cleanup"
	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ids"
	"github.com/desnarong/pgsafe/agent/internal/lock"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/mask"
	"github.com/desnarong/pgsafe/agent/internal/maskrun"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/runlog"
	"github.com/desnarong/pgsafe/agent/internal/scratch"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

// Env is what every operation needs.
type Env struct {
	Config       *config.Config
	Store        *storage.Store
	Runtime      scratch.Runtime
	Logger       *slog.Logger
	AgentVersion string
	// Reporter, when set, receives every run (hosted control plane).
	Reporter Reporter
	// Trigger is recorded on runs: manual (CLI), schedule (daemon) or command (dashboard).
	Trigger   string
	CommandID string
}

// Reporter is told about runs as they start and finish. Implementations must
// never fail or block a run for long (the cloud reporter queues to an outbox).
type Reporter interface {
	Started(o *Outcome)
	Finished(o *Outcome)
}

// With returns a copy of e that records runs with trigger and commandID.
func (e *Env) With(trigger, commandID string) *Env {
	c := *e
	c.Trigger, c.CommandID = trigger, commandID
	return &c
}

// Kinds and statuses.
const (
	KindBackup = "backup"
	KindVerify = "verify"
	KindMask   = "mask"
	KindStage  = "stage"

	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusBlocked = "blocked"
	StatusError   = "error"
	// StatusCancelled: interrupted by shutdown (SIGTERM, --stop-after); not a failure.
	StatusCancelled = "cancelled"
)

// Outcome of one operation.
type Outcome struct {
	Kind      string    `json:"kind"`
	Database  string    `json:"database"`
	RunID     string    `json:"run_id"`
	Status    string    `json:"status"`
	BackupID  string    `json:"backup_id,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Error     string    `json:"error,omitempty"`
	Trigger   string    `json:"trigger,omitempty"`
	CommandID string    `json:"command_id,omitempty"`
	Started   time.Time `json:"started_at"`
	Finished  time.Time `json:"finished_at"`

	Err    error                  `json:"-"`
	Backup *backup.Result         `json:"-"`
	Verify *manifest.VerifyReport `json:"-"`
	Mask   *maskrun.Result        `json:"-"`
	Stage  *StageResult           `json:"-"`
	Scan   *ScanResult            `json:"-"`
	// Nested is the mask run that stage triggered, if any.
	Nested *Outcome `json:"-"`
}

// Code is the process exit code for this outcome.
func (o *Outcome) Code() int {
	switch o.Status {
	case StatusPassed:
		return exitcode.OK
	case StatusBlocked:
		return exitcode.PIIBlocked
	}
	if o.Err != nil {
		return max(exitcode.From(o.Err), exitcode.Failure)
	}
	return exitcode.Failure
}

// NewRuntime builds the scratch runtime from verify.runtime.
func NewRuntime(cfg *config.Config) (scratch.Runtime, error) {
	if cfg.Verify.Runtime == "server" {
		if err := cfg.Require(map[string]string{"verify.server_url": cfg.Verify.ServerURL}); err != nil {
			return nil, exitcode.Config(err)
		}
		ci, err := pg.ParseURL(cfg.Verify.ServerURL)
		if err != nil {
			return nil, exitcode.Config(fmt.Errorf("verify.server_url: %w", err))
		}
		return &scratch.Server{ConnInfo: ci, PGClient: cfg.PGClient, DockerImage: cfg.Verify.DockerImage}, nil
	}
	return &scratch.Docker{ImageTemplate: cfg.Verify.DockerImage, TmpfsBelowBytes: cfg.Verify.TmpfsBelowBytes}, nil
}

// Lock takes db's run lock and, with withCleanup, removes leftovers of
// earlier runs of db that died (their lock is free, so they are orphans).
func (e *Env) Lock(ctx context.Context, db string, withCleanup bool) (func(), error) {
	unlock, err := lock.Database(e.Config.Resolve(e.Config.StateDir), db)
	if err != nil {
		return nil, err
	}
	if withCleanup {
		rep := cleanup.Database(ctx, e.Config, db)
		for _, r := range rep.Removed() {
			e.Logger.Warn("removed leftover from an interrupted run", "db", db, "item", r)
		}
		for _, er := range rep.Errors {
			e.Logger.Warn("cleanup", "db", db, "err", er)
		}
	}
	return unlock, nil
}

func (e *Env) begin(kind, db string) *Outcome {
	start := time.Now().UTC()
	trigger := e.Trigger
	if trigger == "" {
		trigger = "manual"
	}
	o := &Outcome{Kind: kind, Database: db, RunID: ids.Run(start), Status: StatusPassed, Started: start, Trigger: trigger, CommandID: e.CommandID}
	if e.Reporter != nil {
		e.Reporter.Started(o)
	}
	return o
}

// finish sets the status from err and appends the run log.
func (e *Env) finish(ctx context.Context, o *Outcome, err error) *Outcome {
	o.Finished = time.Now().UTC()
	if err != nil {
		o.Err = err
		o.Error = err.Error()
		switch {
		case ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			o.Status = StatusCancelled
		case errors.Is(err, mask.ErrBlocked):
			o.Status = StatusBlocked
		case o.Status == StatusPassed:
			o.Status = StatusFailed
		}
	}
	rl := runlog.Run{ID: o.RunID, Kind: o.Kind, Database: o.Database, BackupID: o.BackupID, Status: o.Status,
		StartedAt: o.Started, FinishedAt: o.Finished, DurationMS: o.Finished.Sub(o.Started).Milliseconds(),
		Summary: o.Summary, Error: o.Error}
	if err := runlog.Append(e.Config.Resolve(e.Config.StateDir), rl); err != nil {
		e.Logger.Warn("could not write run log", "err", err)
	}
	if e.Reporter != nil {
		e.Reporter.Finished(o)
	}
	return o
}

// Backup backs up db.
func (e *Env) Backup(ctx context.Context, db config.Database) *Outcome {
	o := e.begin(KindBackup, db.Name)
	unlock, err := e.Lock(ctx, db.Name, false)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	defer unlock()
	res, err := backup.Run(ctx, backup.Options{Config: e.Config, Database: db, Store: e.Store, Logger: e.Logger, AgentVersion: e.AgentVersion})
	if err == nil {
		o.Backup = res
		m := res.Manifest
		o.BackupID = m.BackupID
		o.Summary = fmt.Sprintf("%s, %d tables", humanBytes(m.SizeBytes), len(m.Tables))
	}
	return e.finish(ctx, o, err)
}

// Verify verifies backupID (newest when empty) of db.
func (e *Env) Verify(ctx context.Context, db config.Database, backupID string) *Outcome {
	o := e.begin(KindVerify, db.Name)
	unlock, err := e.Lock(ctx, db.Name, true)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	defer unlock()
	return e.verify(ctx, o, db, backupID)
}

func (e *Env) verify(ctx context.Context, o *Outcome, db config.Database, backupID string) *Outcome {
	rep, err := verifyRun(ctx, e, db, backupID, o.RunID)
	o.Verify = rep
	if rep != nil {
		o.BackupID = rep.BackupID
		o.Status = rep.Status
		o.Summary = VerifySummary(rep)
		if rep.Status == manifest.StatusFailed && err == nil {
			err = fmt.Errorf("verification failed: %s", o.Summary)
		}
	} else {
		o.Status = StatusError
	}
	return e.finish(ctx, o, err)
}

// VerifySummary is the one-line result of a verify report.
func VerifySummary(r *manifest.VerifyReport) string {
	rto := time.Duration(r.RestoreDurationMS) * time.Millisecond
	switch r.Status {
	case manifest.StatusPassed:
		return fmt.Sprintf("restored in %s, %d/%d tables OK", rto.Round(time.Second), r.TablesOK, r.TablesTotal)
	case manifest.StatusError:
		return "verification error: " + r.Error
	default:
		var failed []string
		for _, c := range r.Checks {
			if c.Status == manifest.StatusFailed {
				failed = append(failed, c.Name)
			}
		}
		return fmt.Sprintf("FAILED: %v", failed)
	}
}

// Mask masks backupID (newest when empty) of db and publishes the masked dump.
func (e *Env) Mask(ctx context.Context, db, backupID string) *Outcome {
	o := e.begin(KindMask, db)
	unlock, err := e.Lock(ctx, db, true)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	defer unlock()
	return e.mask(ctx, o, db, backupID)
}

func (e *Env) mask(ctx context.Context, o *Outcome, db, backupID string) *Outcome {
	res, err := maskrun.Run(ctx, maskrun.Options{
		Config: e.Config, Database: db, Store: e.Store, Runtime: e.Runtime, BackupID: backupID,
		RunID: o.RunID, Logger: e.Logger, AgentVersion: e.AgentVersion,
	})
	o.Mask = res
	if res != nil && res.Masked != nil {
		o.BackupID = res.Masked.SourceBackupID
		o.Summary = res.Masked.BackupID
	}
	return e.finish(ctx, o, err)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
