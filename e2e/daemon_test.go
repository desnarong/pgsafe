//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

// webhookSink collects events posted by the daemon.
type webhookSink struct {
	mu     sync.Mutex
	events []map[string]any
	srv    *httptest.Server
}

func newSink(t *testing.T) *webhookSink {
	s := &webhookSink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e map[string]any
		json.NewDecoder(r.Body).Decode(&e)
		s.mu.Lock()
		s.events = append(s.events, e)
		s.mu.Unlock()
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *webhookSink) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		out = append(out, e["event"].(string))
	}
	return out
}

type runOnceJSON struct {
	Runs []struct {
		Kind, Database, Status, Error string
		BackupID                      string `json:"backup_id"`
	} `json:"runs"`
}

func kinds(r runOnceJSON) string {
	var s []string
	for _, x := range r.Runs {
		s = append(s, x.Kind+":"+x.Status)
	}
	return strings.Join(s, " ")
}

const scheduleAndNotify = `schedule:
  backup: "0 2 * * *"
  verify: after_backup
  stage: after_verify
notify:
  - type: webhook
    url: ${E2E_WEBHOOK}
    on: [failure, blocked, success]
`

// pgsafe run --once: backup → verify → stage, with webhook events.
func TestRunOnce(t *testing.T) {
	sink := newSink(t)
	stagingDB := "e2e_once_" + randHex(3)
	ws := maskWorkspace(t, stagingDB, scheduleAndNotify)
	ws.env = append(ws.env, "E2E_WEBHOOK="+sink.srv.URL)
	ws.mustRun("backup")
	ws.mustRun("scan")
	reviewRules(t, ws)

	var r runOnceJSON
	ws.runJSON(&r, 0, "run", "--once")
	if got := kinds(r); got != "backup:passed verify:passed stage:passed" {
		t.Fatalf("run --once: %s (%+v)", got, r.Runs)
	}
	if r.Runs[1].BackupID != r.Runs[0].BackupID {
		t.Errorf("verify checked %s, not the new backup %s", r.Runs[1].BackupID, r.Runs[0].BackupID)
	}
	if got := strings.Join(sink.names(), " "); got != "backup.passed verify.passed stage.passed" {
		t.Errorf("webhook events: %s", got)
	}
	var customers int
	connect(t, stagingURL(stagingDB)).QueryRow(context.Background(), "select count(*) from customers where email like '%@example.test'").Scan(&customers)
	if customers != 20000 {
		t.Errorf("staging customers masked = %d", customers)
	}
	if _, err := os.Stat(filepath.Join(ws.dir, ".pgsafe", "daemon.json")); err != nil {
		t.Errorf("daemon.json: %v", err)
	}
	assertNoLeftovers(t)
}

// A failing verify stops the pipeline: nothing is staged, a failure event is sent.
func TestRunOnceFailedVerifyDoesNotStage(t *testing.T) {
	sink := newSink(t)
	stagingDB := "e2e_oncefail_" + randHex(3)
	ws := maskWorkspace(t, stagingDB, scheduleAndNotify+"verify:\n  checks:\n    - type: sql\n      name: never\n      query: \"select false\"\n")
	ws.env = append(ws.env, "E2E_WEBHOOK="+sink.srv.URL)
	var r runOnceJSON
	ws.runJSON(&r, 1, "run", "--once")
	if got := kinds(r); got != "backup:passed verify:failed" {
		t.Fatalf("runs: %s", got)
	}
	if got := strings.Join(sink.names(), " "); got != "backup.passed verify.failed" {
		t.Errorf("webhook events: %s", got)
	}
	var exists bool
	connect(t, stagingAdminURL()).QueryRow(context.Background(), "select exists(select 1 from pg_database where datname = $1)", stagingDB).Scan(&exists)
	if exists {
		t.Error("staging database was created although verify failed")
	}
}

// The daemon runs on its schedule, catches up a missed backup at start, and
// stops cleanly.
func TestDaemonSchedule(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "none", "schedule:\n  backup: \"@every 12s\"\n  verify: after_backup\n  stage: \"off\"\n")
	r := ws.run("run", "--print-schedule")
	if r.code != 0 || !strings.Contains(r.stdout, "shop16 pipeline (@every 12s)") {
		t.Fatalf("print-schedule: %d %s %s", r.code, r.stdout, r.stderr)
	}
	t0 := time.Now()
	r = ws.run("run", "--stop-after", "40s", "--log-format", "json")
	if r.code != 0 {
		t.Fatalf("daemon exit %d\n%s", r.code, r.stderr)
	}
	if d := time.Since(t0); d < 38*time.Second || d > 4*time.Minute {
		t.Errorf("daemon ran for %s", d)
	}
	if !strings.Contains(r.stderr, `"msg":"missed a scheduled backup; running it now"`) {
		t.Errorf("no catch-up at start:\n%s", r.stderr)
	}
	var runs struct {
		Runs []struct{ Kind, Status, Error string } `json:"runs"`
	}
	ws.runJSON(&runs, 0, "list", "runs", "--limit", "0")
	counts := map[string]int{}
	for _, x := range runs.Runs {
		if x.Status == "cancelled" { // the run in flight when --stop-after fired
			continue
		}
		if x.Status != "passed" {
			t.Errorf("run %s %s: %s", x.Kind, x.Status, x.Error)
		}
		counts[x.Kind]++
	}
	if counts["backup"] < 2 || counts["verify"] < 2 {
		t.Errorf("runs: %v (want >= 2 backups and verifies)", counts)
	}
	assertNoLeftovers(t)
}

func holdLock(t *testing.T, ws *workspace, name string) func() {
	t.Helper()
	p := filepath.Join(ws.dir, ".pgsafe", "locks", name+".lock")
	os.MkdirAll(filepath.Dir(p), 0o700)
	fl := flock.New(p)
	if ok, err := fl.TryLock(); err != nil || !ok {
		t.Fatalf("lock %s: %v %v", name, ok, err)
	}
	return func() { fl.Unlock() }
}

// Runs never overlap: a second daemon and a run of a busy database are refused.
func TestLocks(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "none", "schedule:\n  backup: \"0 2 * * *\"\n")
	release := holdLock(t, ws, "daemon")
	if r := ws.run("run", "--once"); r.code != 1 || !strings.Contains(r.stderr, "already running") {
		t.Errorf("second daemon: exit %d %s", r.code, r.stderr)
	}
	release()
	release = holdLock(t, ws, "db-shop16")
	if r := ws.run("backup"); r.code != 1 || !strings.Contains(r.stdout+r.stderr, "in progress for database shop16") {
		t.Errorf("backup while locked: exit %d %s %s", r.code, r.stdout, r.stderr)
	}
	release()
	ws.mustRun("backup")
}

func scratchContainers(t *testing.T, db string) []string {
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}", "--filter", "label=pgsafe.db="+db).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))
}

// §8 Cleanup: kill the agent in the middle of verify; the next run removes the
// orphaned scratch container.
func TestCleanupAfterKill(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "age", "")
	ws.mustRun("backup")

	cmd := exec.Command(pgsafeBin, "verify")
	cmd.Dir, cmd.Env = ws.dir, ws.env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	var orphan []string
	for time.Now().Before(deadline) {
		if orphan = scratchContainers(t, "shop16"); len(orphan) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if len(orphan) == 0 {
		t.Fatal("scratch container never appeared")
	}
	if left := scratchContainers(t, "shop16"); len(left) == 0 {
		t.Fatal("expected the killed run to leave its container behind")
	}

	r := ws.mustRun("verify")
	if !strings.Contains(r.stderr, "removed leftover from an interrupted run") || !strings.Contains(r.stderr, orphan[0]) {
		t.Errorf("verify did not report the cleanup:\n%s", r.stderr)
	}
	if left := scratchContainers(t, "shop16"); len(left) != 0 {
		t.Errorf("containers left: %v", left)
	}
	assertNoLeftovers(t)
}

// pgsafe cleanup drops tagged scratch/staging databases of dead runs, and
// nothing that belongs to another database.
func TestCleanupDatabases(t *testing.T) {
	stagingDB := "e2e_clean_" + randHex(3)
	ws := maskWorkspace(t, stagingDB, "verify:\n  runtime: server\n  server_url: ${E2E_SCRATCH_URL}\n")
	ws.env = append(ws.env, "E2E_SCRATCH_URL="+stagingAdminURL())
	admin := connect(t, stagingAdminURL())
	ctx := context.Background()
	mk := func(name, owner string) {
		if _, err := admin.Exec(ctx, "create database "+name); err != nil {
			t.Fatal(err)
		}
		admin.Exec(ctx, "comment on database "+name+" is 'pgsafe db="+owner+"'")
		t.Cleanup(func() { dropStagingDB(t, name) })
	}
	mk("pgsafe_verify_orphan"+randHex(2), "shop16")
	mk(stagingDB+"_pgsafe_new_orphan", "shop16")
	other := "pgsafe_verify_other" + randHex(2)
	mk(other, "someotherdb")

	var rep struct {
		Databases []string `json:"databases"`
	}
	ws.runJSON(&rep, 0, "cleanup")
	if len(rep.Databases) != 2 {
		t.Fatalf("cleanup removed %v, want the 2 shop16 databases", rep.Databases)
	}
	var n int
	admin.QueryRow(ctx, "select count(*) from pg_database where datname like 'pgsafe_verify_orphan%' or datname = $1", stagingDB+"_pgsafe_new_orphan").Scan(&n)
	if n != 0 {
		t.Errorf("%d orphan databases still exist", n)
	}
	admin.QueryRow(ctx, "select count(*) from pg_database where datname = $1", other).Scan(&n)
	if n != 1 {
		t.Error("cleanup dropped a database owned by another pgsafe database")
	}
}
