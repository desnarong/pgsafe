package scheduler

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/ops"
	"github.com/desnarong/pgsafe/shared/apitypes"
)

func cfgWith(t *testing.T, s config.Schedule, targets int) *config.Config {
	t.Helper()
	c := &config.Config{Databases: []config.Database{{Name: "a"}, {Name: "b"}}, Schedule: s, StateDir: t.TempDir()}
	for i := 0; i < targets; i++ {
		c.Staging.Targets = append(c.Staging.Targets, config.StagingTarget{Type: "s3"})
	}
	return c
}

func TestPlan(t *testing.T) {
	jobs, err := Plan(cfgWith(t, config.Schedule{Backup: "0 2 * * *", Verify: "after_backup", Stage: "after_verify"}, 1))
	if err != nil || len(jobs) != 2 || jobs[0].Kind != JobPipeline {
		t.Fatalf("chained: %v %+v", err, jobs)
	}
	jobs, err = Plan(cfgWith(t, config.Schedule{Backup: "@every 6h", Verify: "30 3 * * *", Stage: "0 4 * * 1"}, 1))
	if err != nil || len(jobs) != 6 {
		t.Fatalf("separate crons: %v %d", err, len(jobs))
	}
	bad := []config.Schedule{
		{Backup: "0 2 * * *", Verify: "off", Stage: "after_verify"},
		{Verify: "after_backup"},
		{},
		{Backup: "0 2 * * *", Stage: "0 4 * * *"}, // stage without targets
	}
	for _, s := range bad {
		if _, err := Plan(cfgWith(t, s, 0)); err == nil {
			t.Errorf("%+v should be rejected", s)
		}
	}
}

func TestCatchUp(t *testing.T) {
	daily, _ := cron.ParseStandard("0 2 * * *")
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.Local)
	tick := time.Date(2026, 11, 5, 2, 0, 0, 0, time.Local)
	if got := PrevTick(daily, now); !got.Equal(tick) {
		t.Fatalf("PrevTick = %v, want %v", got, tick)
	}
	ok := tick.Add(3 * time.Minute)
	missed := tick.Add(-20 * time.Hour)
	if NeedsCatchUp(daily, &ok, now) {
		t.Error("backup after the last tick: no catch-up")
	}
	if !NeedsCatchUp(daily, &missed, now) {
		t.Error("backup before the last tick: catch-up")
	}
	if !NeedsCatchUp(daily, nil, now) {
		t.Error("no backup at all: catch-up")
	}
	every, _ := cron.ParseStandard("@every 1h")
	recent := now.Add(-10 * time.Minute)
	old := now.Add(-3 * time.Hour)
	if NeedsCatchUp(every, &recent, now) || !NeedsCatchUp(every, &old, now) {
		t.Error("@every catch-up")
	}
}

// fakeRunner records calls and returns scripted statuses.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	verify  string
	trigger string
	running chan struct{}
	release chan struct{}
}

func (f *fakeRunner) add(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeRunner) Backup(ctx context.Context, db config.Database) *ops.Outcome {
	f.add("backup " + db.Name)
	if f.running != nil {
		f.running <- struct{}{}
		<-f.release
	}
	return &ops.Outcome{Kind: "backup", Database: db.Name, Status: ops.StatusPassed, BackupID: "bk_" + db.Name}
}

func (f *fakeRunner) Verify(ctx context.Context, db config.Database, id string) *ops.Outcome {
	f.add("verify " + db.Name + " " + id)
	st := f.verify
	if st == "" {
		st = ops.StatusPassed
	}
	return &ops.Outcome{Kind: "verify", Database: db.Name, Status: st}
}

func (f *fakeRunner) Stage(ctx context.Context, db, masked string) *ops.Outcome {
	f.add("stage " + db)
	return &ops.Outcome{Kind: "stage", Database: db, Status: ops.StatusPassed}
}

func (f *fakeRunner) Scan(ctx context.Context, db config.Database, so ops.ScanOptions) *ops.Outcome {
	f.add("scan " + db.Name)
	return &ops.Outcome{Kind: "scan", Database: db.Name, Status: ops.StatusPassed}
}

func (f *fakeRunner) Mask(ctx context.Context, db, backupID string) *ops.Outcome {
	f.add("mask " + db)
	return &ops.Outcome{Kind: "mask", Database: db, Status: ops.StatusPassed}
}

func (f *fakeRunner) With(trigger, commandID string) Runner {
	f.mu.Lock()
	f.trigger = trigger + ":" + commandID
	f.mu.Unlock()
	return f
}

func newDaemon(t *testing.T, s config.Schedule, r Runner) *Daemon {
	return &Daemon{Config: cfgWith(t, s, 1), Runner: r, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestRunOncePipeline(t *testing.T) {
	r := &fakeRunner{}
	d := newDaemon(t, config.Schedule{Backup: "0 2 * * *", Verify: "after_backup", Stage: "after_verify"}, r)
	out := d.RunOnce(context.Background())
	want := "backup a|verify a bk_a|stage a|backup b|verify b bk_b|stage b"
	if got := strings.Join(r.calls, "|"); got != want {
		t.Fatalf("calls %s\nwant  %s", got, want)
	}
	if len(out) != 6 {
		t.Fatalf("outcomes %d", len(out))
	}
}

func TestFailedVerifyNeverStages(t *testing.T) {
	r := &fakeRunner{verify: ops.StatusFailed}
	d := newDaemon(t, config.Schedule{Backup: "0 2 * * *", Verify: "after_backup", Stage: "after_verify"}, r)
	d.RunOnce(context.Background())
	for _, c := range r.calls {
		if strings.HasPrefix(c, "stage") {
			t.Fatalf("staged after a failed verify: %v", r.calls)
		}
	}
}

func TestDispatchSkipsBusyDatabase(t *testing.T) {
	r := &fakeRunner{running: make(chan struct{}), release: make(chan struct{})}
	d := newDaemon(t, config.Schedule{Backup: "@every 1h", Verify: "off", Stage: "off"}, r)
	d.MaxConcurrent = 2
	d.init()
	j := Job{Database: "a", Kind: JobPipeline}
	go d.dispatch(context.Background(), j)
	<-r.running
	d.dispatch(context.Background(), j) // same db while busy: skipped, returns immediately
	close(r.release)
	time.Sleep(50 * time.Millisecond)
	if n := strings.Count(strings.Join(r.calls, "|"), "backup a"); n != 1 {
		t.Fatalf("backups of a = %d, want 1", n)
	}
}

func TestPlanForOverrides(t *testing.T) {
	cfg := cfgWith(t, config.Schedule{Backup: "0 2 * * *", Verify: "after_backup"}, 1)
	jobs, err := PlanFor(cfg, map[string]config.Schedule{"b": {Backup: "@every 1h", Verify: "off"}})
	if err != nil {
		t.Fatal(err)
	}
	specs := map[string]string{}
	for _, j := range jobs {
		specs[j.Database] = j.Spec
	}
	if specs["a"] != "0 2 * * *" || specs["b"] != "@every 1h" {
		t.Fatalf("specs %v", specs)
	}
}

// fakeCloud delivers one command and records results.
type fakeCloud struct {
	mu      sync.Mutex
	cmds    []apitypes.Command
	results map[string]apitypes.CommandResult
}

func (f *fakeCloud) Heartbeat(ctx context.Context) (int64, error) { return 1, nil }
func (f *fakeCloud) Sync(ctx context.Context) (map[string]config.Schedule, error) {
	return nil, nil
}
func (f *fakeCloud) Commands(ctx context.Context, wait time.Duration) ([]apitypes.Command, error) {
	f.mu.Lock()
	c := f.cmds
	f.cmds = nil
	f.mu.Unlock()
	if len(c) == 0 {
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	return c, nil
}
func (f *fakeCloud) CommandDone(ctx context.Context, id string, res apitypes.CommandResult) error {
	f.mu.Lock()
	f.results[id] = res
	f.mu.Unlock()
	return nil
}

func TestDaemonRunsCommands(t *testing.T) {
	r := &fakeRunner{}
	fc := &fakeCloud{results: map[string]apitypes.CommandResult{}, cmds: []apitypes.Command{
		{ID: "cmd_1", Database: "a", Kind: "scan"}, {ID: "cmd_2", Database: "zzz", Kind: "backup"}}}
	d := newDaemon(t, config.Schedule{Backup: "0 2 * * *", Verify: "off", Stage: "off"}, r)
	d.Cloud = fc
	jobs, _ := Plan(d.Config)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d.Run(ctx, jobs, false)
	if got := fc.results["cmd_1"]; got.Status != "done" {
		t.Errorf("cmd_1: %+v", got)
	}
	if got := fc.results["cmd_2"]; got.Status != "failed" || got.Error == "" {
		t.Errorf("cmd_2 (unknown db): %+v", got)
	}
	if !strings.Contains(strings.Join(r.calls, "|"), "scan a") || r.trigger != "command:cmd_1" && r.trigger != "command:cmd_2" {
		t.Errorf("calls %v trigger %s", r.calls, r.trigger)
	}
}
