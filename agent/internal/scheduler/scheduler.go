package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/notify"
	"github.com/desnarong/pgsafe/agent/internal/ops"
	"github.com/desnarong/pgsafe/shared/apitypes"
)

// Job kinds. A pipeline is backup, then (after_backup) verify, then (after_verify) stage.
const (
	JobPipeline = "pipeline"
	JobVerify   = "verify"
	JobStage    = "stage"
)

// Job is one scheduled entry.
type Job struct {
	Database string
	Kind     string
	Spec     string
	Sched    cron.Schedule
}

func chained(v string) bool { return v == "after_backup" || v == "after_verify" }
func enabled(v string) bool { return v != "" && v != "off" }

// Plan turns the config's schedule into jobs, one set per database.
func Plan(cfg *config.Config) ([]Job, error) { return PlanFor(cfg, nil) }

// PlanFor is Plan with per-database schedule overrides (managed in the dashboard).
func PlanFor(cfg *config.Config, overrides map[string]config.Schedule) ([]Job, error) {
	var jobs []Job
	add := func(db, kind, spec string) error {
		sc, err := cron.ParseStandard(spec)
		if err != nil {
			return fmt.Errorf("%s: schedule %s %q: %w", db, kind, spec, err)
		}
		jobs = append(jobs, Job{Database: db, Kind: kind, Spec: spec, Sched: sc})
		return nil
	}
	for _, d := range cfg.Databases {
		s := cfg.Schedule
		if o, ok := overrides[d.Name]; ok {
			s = o
		}
		if s.Stage == "after_verify" && !enabled(s.Verify) {
			return nil, fmt.Errorf("%s: schedule.stage after_verify needs schedule.verify (after_backup or a cron)", d.Name)
		}
		if s.Verify == "after_backup" && s.Backup == "" {
			return nil, fmt.Errorf("%s: schedule.verify after_backup needs schedule.backup", d.Name)
		}
		if enabled(s.Stage) && len(cfg.Staging.Targets) == 0 {
			return nil, fmt.Errorf("%s: schedule.stage is enabled but staging.targets is empty", d.Name)
		}
		if s.Backup != "" {
			if err := add(d.Name, JobPipeline, s.Backup); err != nil {
				return nil, err
			}
		}
		if enabled(s.Verify) && !chained(s.Verify) {
			if err := add(d.Name, JobVerify, s.Verify); err != nil {
				return nil, err
			}
		}
		if enabled(s.Stage) && !chained(s.Stage) {
			if err := add(d.Name, JobStage, s.Stage); err != nil {
				return nil, err
			}
		}
	}
	if len(jobs) == 0 {
		return nil, errors.New("nothing scheduled: set schedule.backup (cron like \"0 2 * * *\" or \"@every 6h\")")
	}
	return jobs, nil
}

// PrevTick returns the latest scheduled time at or before now (zero if none
// within the last 400 days).
func PrevTick(s cron.Schedule, now time.Time) time.Time {
	start := now.AddDate(0, 0, -400)
	if d, ok := s.(cron.ConstantDelaySchedule); ok {
		start = now.Add(-d.Delay - time.Second)
	}
	var last time.Time
	for t := s.Next(start); !t.After(now); t = s.Next(t) {
		last = t
	}
	return last
}

// NeedsCatchUp reports whether a backup that should have happened is missing.
func NeedsCatchUp(s cron.Schedule, lastBackup *time.Time, now time.Time) bool {
	if d, ok := s.(cron.ConstantDelaySchedule); ok {
		// @every ticks are relative to daemon start: catch up when the newest
		// backup is older than one interval.
		return lastBackup == nil || now.Sub(*lastBackup) > d.Delay
	}
	tick := PrevTick(s, now)
	if tick.IsZero() {
		return lastBackup == nil
	}
	return lastBackup == nil || lastBackup.Before(tick)
}

// Runner runs operations. EnvRunner adapts *ops.Env.
type Runner interface {
	Backup(ctx context.Context, db config.Database) *ops.Outcome
	Verify(ctx context.Context, db config.Database, backupID string) *ops.Outcome
	Scan(ctx context.Context, db config.Database, so ops.ScanOptions) *ops.Outcome
	Mask(ctx context.Context, db, backupID string) *ops.Outcome
	Stage(ctx context.Context, db, maskedID string) *ops.Outcome
	// With returns a runner that records runs with trigger and commandID.
	With(trigger, commandID string) Runner
}

// EnvRunner adapts *ops.Env to Runner.
type EnvRunner struct{ *ops.Env }

func (e EnvRunner) With(trigger, commandID string) Runner {
	return EnvRunner{e.Env.With(trigger, commandID)}
}

// CloudLink is the daemon's connection to the control plane (optional).
type CloudLink interface {
	// Heartbeat reports liveness and returns the current config version.
	Heartbeat(ctx context.Context) (int64, error)
	Commands(ctx context.Context, wait time.Duration) ([]apitypes.Command, error)
	CommandDone(ctx context.Context, id string, res apitypes.CommandResult) error
	// Sync applies reviewed rules and returns schedules managed in the dashboard.
	Sync(ctx context.Context) (map[string]config.Schedule, error)
}

// Daemon schedules and runs jobs.
type Daemon struct {
	Config        *config.Config
	Runner        Runner
	Notifier      *notify.Notifier
	Logger        *slog.Logger
	MaxConcurrent int
	AgentVersion  string
	Cloud         CloudLink
	// HeartbeatEvery defaults to 60s.
	HeartbeatEvery time.Duration
	// LatestBackup returns the newest backup time of db (nil if none), for catch-up.
	LatestBackup func(ctx context.Context, db string) (*time.Time, error)

	mu        sync.Mutex
	dbLocks   map[string]*sync.Mutex
	sem       chan struct{}
	state     State
	stateDir  string
	overrides map[string]config.Schedule

	cron    *cron.Cron
	entries map[cron.EntryID]Job
}

// State is written to state_dir/daemon.json.
type State struct {
	PID          int                 `json:"pid"`
	AgentVersion string              `json:"agent_version"`
	StartedAt    time.Time           `json:"started_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
	Cloud        bool                `json:"cloud"`
	Databases    map[string]*DBState `json:"databases"`
}

type DBState struct {
	Next map[string]time.Time `json:"next"`
	Last []*ops.Outcome       `json:"last"` // most recent outcome per kind
}

func (d *Daemon) init() {
	if d.MaxConcurrent <= 0 {
		d.MaxConcurrent = 1
	}
	if d.HeartbeatEvery <= 0 {
		d.HeartbeatEvery = time.Minute
	}
	d.sem = make(chan struct{}, d.MaxConcurrent)
	d.dbLocks = map[string]*sync.Mutex{}
	d.stateDir = d.Config.Resolve(d.Config.StateDir)
	d.state = State{PID: os.Getpid(), AgentVersion: d.AgentVersion, StartedAt: time.Now().UTC(), Cloud: d.Cloud != nil, Databases: map[string]*DBState{}}
	for _, db := range d.Config.Databases {
		d.dbLocks[db.Name] = &sync.Mutex{}
		d.state.Databases[db.Name] = &DBState{Next: map[string]time.Time{}}
	}
}

func (d *Daemon) database(name string) (config.Database, bool) {
	db, err := d.Config.Database(name)
	if err != nil {
		return config.Database{}, false
	}
	return *db, true
}

func (d *Daemon) scheduleFor(db string) config.Schedule {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.overrides[db]; ok {
		return s
	}
	return d.Config.Schedule
}

// syncCloud applies reviewed rules and managed schedules (best effort).
func (d *Daemon) syncCloud(ctx context.Context) (changed bool) {
	if d.Cloud == nil {
		return false
	}
	managed, err := d.Cloud.Sync(ctx)
	if err != nil {
		d.Logger.Warn("could not sync config from the control plane", "err", err)
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if reflect.DeepEqual(managed, d.overrides) || (len(managed) == 0 && len(d.overrides) == 0) {
		return false
	}
	d.overrides = managed
	return true
}

// RunOnce runs every enabled step for every database once, now.
func (d *Daemon) RunOnce(ctx context.Context) []*ops.Outcome {
	d.init()
	if d.Cloud != nil {
		if _, err := d.Cloud.Heartbeat(ctx); err != nil {
			d.Logger.Warn("control plane heartbeat failed", "err", err)
		}
		d.syncCloud(ctx)
	}
	var all []*ops.Outcome
	runner := d.Runner.With("manual", "")
	for _, db := range d.Config.Databases {
		all = append(all, d.pipeline(ctx, runner, db, true)...)
	}
	d.writeState()
	return all
}

// pipeline runs backup → verify → stage as configured. With once, cron-scheduled
// verify/stage also run (a one-off full cycle).
func (d *Daemon) pipeline(ctx context.Context, r Runner, db config.Database, once bool) []*ops.Outcome {
	s := d.scheduleFor(db.Name)
	verifyOn := s.Verify == "after_backup" || (once && enabled(s.Verify))
	stageOn := s.Stage == "after_verify" || (once && enabled(s.Stage))

	var out []*ops.Outcome
	b := d.record(ctx, r.Backup(ctx, db))
	out = append(out, b)
	if b.Status != ops.StatusPassed || !verifyOn || ctx.Err() != nil {
		return out
	}
	v := d.record(ctx, r.Verify(ctx, db, b.BackupID))
	out = append(out, v)
	if v.Status != ops.StatusPassed || !stageOn || ctx.Err() != nil {
		return out // never publish data from a backup that did not verify
	}
	return append(out, d.record(ctx, r.Stage(ctx, db.Name, "")))
}

// record notifies, logs and stores an outcome.
func (d *Daemon) record(ctx context.Context, o *ops.Outcome) *ops.Outcome {
	attrs := []any{"db", o.Database, "kind", o.Kind, "status", o.Status, "run_id", o.RunID, "trigger", o.Trigger}
	if o.Summary != "" {
		attrs = append(attrs, "summary", o.Summary)
	}
	if o.Status == ops.StatusPassed {
		d.Logger.Info("run finished", attrs...)
	} else {
		d.Logger.Error("run finished", append(attrs, "err", o.Error)...)
	}
	if d.Notifier != nil && o.Status != ops.StatusCancelled {
		d.Notifier.Send(context.WithoutCancel(ctx), notify.Event{Kind: o.Kind, Database: o.Database, Status: o.Status,
			RunID: o.RunID, BackupID: o.BackupID, Summary: o.Summary, Error: o.Error, AgentVersion: d.AgentVersion})
	}
	d.mu.Lock()
	if st := d.state.Databases[o.Database]; st != nil {
		kept := st.Last[:0]
		for _, l := range st.Last {
			if l.Kind != o.Kind {
				kept = append(kept, l)
			}
		}
		st.Last = append(kept, o)
		sort.Slice(st.Last, func(i, j int) bool { return st.Last[i].Kind < st.Last[j].Kind })
	}
	d.mu.Unlock()
	d.writeState()
	return o
}

// dispatch runs a scheduled job unless the same database is already busy.
func (d *Daemon) dispatch(ctx context.Context, j Job) {
	if ctx.Err() != nil {
		return
	}
	dl := d.dbLocks[j.Database]
	if !dl.TryLock() {
		d.Logger.Warn("skipping scheduled run: previous run of this database is still going", "db", j.Database, "job", j.Kind)
		return
	}
	defer dl.Unlock()
	if !d.acquire(ctx) {
		return
	}
	defer d.release()

	db, ok := d.database(j.Database)
	if !ok {
		return
	}
	r := d.Runner.With("schedule", "")
	switch j.Kind {
	case JobPipeline:
		d.pipeline(ctx, r, db, false)
	case JobVerify:
		v := d.record(ctx, r.Verify(ctx, db, ""))
		if v.Status == ops.StatusPassed && d.scheduleFor(db.Name).Stage == "after_verify" && ctx.Err() == nil {
			d.record(ctx, r.Stage(ctx, db.Name, ""))
		}
	case JobStage:
		d.record(ctx, r.Stage(ctx, db.Name, ""))
	}
}

func (d *Daemon) acquire(ctx context.Context) bool {
	select {
	case d.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (d *Daemon) release() { <-d.sem }

// runCommand executes a "run now" command from the dashboard. Unlike a
// scheduled run it waits for a busy database instead of skipping.
func (d *Daemon) runCommand(ctx context.Context, c apitypes.Command) {
	res := apitypes.CommandResult{Status: "failed"}
	defer func() {
		if err := d.Cloud.CommandDone(context.WithoutCancel(ctx), c.ID, res); err != nil {
			d.Logger.Warn("could not report command result", "command", c.ID, "err", err)
		}
	}()
	db, ok := d.database(c.Database)
	if !ok {
		res.Error = "database " + c.Database + " is not configured on this agent"
		return
	}
	dl := d.dbLocks[c.Database]
	dl.Lock()
	defer dl.Unlock()
	if !d.acquire(ctx) {
		res.Error = "agent is shutting down"
		return
	}
	defer d.release()

	d.Logger.Info("running command from the dashboard", "command", c.ID, "db", c.Database, "kind", c.Kind)
	r := d.Runner.With("command", c.ID)
	var o *ops.Outcome
	switch c.Kind {
	case "backup":
		o = r.Backup(ctx, db)
	case "verify":
		o = r.Verify(ctx, db, "")
	case "scan":
		o = r.Scan(ctx, db, ops.ScanOptions{})
	case "mask":
		o = r.Mask(ctx, db.Name, "")
	case "stage":
		o = r.Stage(ctx, db.Name, "")
	default:
		res.Error = "unknown command kind " + c.Kind
		return
	}
	d.record(ctx, o)
	res.RunID, res.Error = o.RunID, o.Error
	if o.Status == ops.StatusPassed {
		res.Status = "done"
	}
}

// Run schedules jobs until ctx is cancelled, then waits for running jobs.
func (d *Daemon) Run(ctx context.Context, jobs []Job, catchUp bool) error {
	d.init()
	var wg sync.WaitGroup
	if d.Cloud != nil {
		if _, err := d.Cloud.Heartbeat(ctx); err != nil {
			d.Logger.Warn("control plane heartbeat failed", "err", err)
		}
		if d.syncCloud(ctx) {
			if replanned, err := PlanFor(d.Config, d.overrides); err == nil {
				jobs = replanned
			} else {
				d.Logger.Error("schedule from the dashboard is invalid; keeping pgsafe.yaml", "err", err)
			}
		}
	}

	d.cron = cron.New(cron.WithLocation(time.Local))
	d.entries = map[cron.EntryID]Job{}
	d.schedule(ctx, jobs)

	if catchUp && d.LatestBackup != nil {
		for _, j := range jobs {
			if j.Kind != JobPipeline {
				continue
			}
			last, err := d.LatestBackup(ctx, j.Database)
			if err != nil {
				d.Logger.Warn("catch-up check failed", "db", j.Database, "err", err)
				continue
			}
			if NeedsCatchUp(j.Sched, last, time.Now()) {
				d.Logger.Info("missed a scheduled backup; running it now", "db", j.Database)
				wg.Add(1)
				go func(j Job) { defer wg.Done(); d.dispatch(ctx, j) }(j)
			}
		}
	}
	d.cron.Start()
	d.Logger.Info("pgsafe daemon started", "jobs", len(jobs), "max_concurrent", d.MaxConcurrent, "cloud", d.Cloud != nil)
	d.refreshNext()

	if d.Cloud != nil {
		wg.Add(2)
		go func() { defer wg.Done(); d.heartbeatLoop(ctx) }()
		go func() { defer wg.Done(); d.commandLoop(ctx, &wg) }()
	}

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for running := true; running; {
		select {
		case <-ctx.Done():
			running = false
		case <-tick.C:
			d.refreshNext()
		}
	}
	d.Logger.Info("pgsafe daemon stopping: waiting for running jobs")
	stopped := d.cron.Stop()
	done := make(chan struct{})
	go func() { wg.Wait(); <-stopped.Done(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		d.Logger.Warn("timed out waiting for running jobs")
	}
	d.writeState()
	return nil
}

func (d *Daemon) schedule(ctx context.Context, jobs []Job) {
	for id := range d.entries {
		d.cron.Remove(id)
	}
	d.entries = map[cron.EntryID]Job{}
	for _, j := range jobs {
		j := j
		id := d.cron.Schedule(j.Sched, cron.FuncJob(func() { d.dispatch(ctx, j) }))
		d.entries[id] = j
	}
}

func (d *Daemon) heartbeatLoop(ctx context.Context) {
	last := int64(-1)
	t := time.NewTicker(d.HeartbeatEvery)
	defer t.Stop()
	for {
		ver, err := d.Cloud.Heartbeat(ctx)
		if err != nil && ctx.Err() == nil {
			d.Logger.Warn("control plane heartbeat failed", "err", err)
		} else if err == nil && ver != last {
			if last != -1 && d.syncCloud(ctx) {
				if jobs, err := PlanFor(d.Config, d.overrides); err != nil {
					d.Logger.Error("schedule from the dashboard is invalid; keeping the current one", "err", err)
				} else {
					d.mu.Lock()
					d.schedule(ctx, jobs)
					d.mu.Unlock()
					d.Logger.Info("schedule updated from the dashboard", "jobs", len(jobs))
					d.refreshNext()
				}
			} else if last != -1 {
				d.Logger.Debug("config changed in the dashboard; rules synced")
			}
			last = ver
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) commandLoop(ctx context.Context, wg *sync.WaitGroup) {
	backoff := time.Second
	for ctx.Err() == nil {
		cmds, err := d.Cloud.Commands(ctx, 30*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.Logger.Debug("command poll failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, c := range cmds {
			if c.Kind == "mask" || c.Kind == "stage" {
				d.syncCloud(ctx) // pick up rules reviewed moments ago
			}
			wg.Add(1)
			go func(c apitypes.Command) { defer wg.Done(); d.runCommand(ctx, c) }(c)
		}
	}
}

func (d *Daemon) refreshNext() {
	d.mu.Lock()
	for _, st := range d.state.Databases {
		st.Next = map[string]time.Time{}
	}
	if d.cron != nil {
		for _, e := range d.cron.Entries() {
			if j, ok := d.entries[e.ID]; ok {
				if st := d.state.Databases[j.Database]; st != nil {
					st.Next[j.Kind] = e.Next
				}
			}
		}
	}
	d.mu.Unlock()
	d.writeState()
}

func (d *Daemon) writeState() {
	d.mu.Lock()
	d.state.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(d.state, "", "  ")
	d.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.MkdirAll(d.stateDir, 0o700); err != nil {
		return
	}
	p := filepath.Join(d.stateDir, "daemon.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, p)
	}
}

// Upcoming lists the next n run times of each job (for --print-schedule).
func Upcoming(jobs []Job, now time.Time, n int) map[string][]time.Time {
	out := map[string][]time.Time{}
	for _, j := range jobs {
		key := j.Database + " " + j.Kind + " (" + j.Spec + ")"
		t := now
		for i := 0; i < n; i++ {
			t = j.Sched.Next(t)
			out[key] = append(out[key], t)
		}
	}
	return out
}
