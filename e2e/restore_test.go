//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// §3.9 restore: confirmation, new database by default, --replace keeps the old one, audit log.
func TestRestore(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "age", "")
	ws.mustRun("backup")
	name := "e2e_restored_" + randHex(3)
	target := stagingURL(name)
	t.Cleanup(func() {
		dropStagingDB(t, name)
		conn, err := pgx.Connect(context.Background(), stagingAdminURL())
		if err != nil {
			return
		}
		defer conn.Close(context.Background())
		rows, _ := conn.Query(context.Background(), "select datname from pg_database where datname like $1", name+"_pgsafe_old_%")
		olds, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, o := range olds {
			dropStagingDB(t, o)
		}
	})

	r := ws.run("restore", "--backup", "latest", "--to", target)
	if r.code != 2 || !strings.Contains(r.stderr, "--confirm-db="+name) {
		t.Fatalf("no confirmation: exit %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "pg_restore --no-owner --no-privileges") || !strings.Contains(r.stdout, "age -d -i") {
		t.Errorf("equivalent commands missing:\n%s", r.stdout)
	}
	if r := ws.run("restore", "--backup", "latest", "--to", target, "--yes", "--confirm-db", "wrong"); r.code != 2 {
		t.Fatalf("wrong confirm-db: exit %d", r.code)
	}

	var out struct {
		Status   string                          `json:"status"`
		BackupID string                          `json:"backup_id"`
		Checks   []struct{ Name, Status string } `json:"checks"`
	}
	ws.runJSON(&out, 0, "restore", "--backup", "latest", "--to", target, "--yes", "--confirm-db", name)
	if out.Status != "passed" || len(out.Checks) < 4 {
		t.Fatalf("restore: %+v", out)
	}
	for _, c := range out.Checks {
		if c.Status != "passed" {
			t.Errorf("check %s = %s", c.Name, c.Status)
		}
	}
	conn := connect(t, target)
	for table, want := range wantRows {
		var got int64
		err := conn.QueryRow(context.Background(), "select count(*) from "+pgx.Identifier{table}.Sanitize()).Scan(&got)
		switch table {
		case "audit_raw_logs": // excluded from backups
			if err == nil {
				t.Errorf("excluded table %s was restored", table)
			}
			continue
		case "sessions", "cache_pages": // schema only
			want = 0
		}
		if err != nil || got != want {
			t.Errorf("%s: %d rows (%v), want %d", table, got, err, want)
		}
	}
	conn.Close(context.Background())

	if r := ws.run("restore", "--backup", out.BackupID, "--to", target, "--yes", "--confirm-db", name); r.code != 2 || !strings.Contains(r.stdout+r.stderr, "already exists") {
		t.Fatalf("restore over existing db without --replace: exit %d %s %s", r.code, r.stdout, r.stderr)
	}

	var rep struct {
		Result struct {
			Replaced bool   `json:"replaced"`
			KeptAs   string `json:"kept_as"`
		} `json:"result"`
	}
	ws.runJSON(&rep, 0, "restore", "--backup", out.BackupID, "--to", target, "--replace", "--yes", "--confirm-db", name)
	if !rep.Result.Replaced || !strings.HasPrefix(rep.Result.KeptAs, name+"_pgsafe_old_") {
		t.Fatalf("--replace: %+v", rep.Result)
	}
	var kept bool
	connect(t, stagingAdminURL()).QueryRow(context.Background(), "select exists(select 1 from pg_database where datname = $1)", rep.Result.KeptAs).Scan(&kept)
	if !kept {
		t.Error("previous database was not kept")
	}

	f, err := os.Open(filepath.Join(ws.dir, ".pgsafe", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var statuses []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e struct{ Action, Status, Actor, Target string }
		json.Unmarshal(sc.Bytes(), &e)
		if e.Action != "restore" || e.Actor == "" || strings.Contains(e.Target, ":pgsafe@") {
			t.Errorf("audit entry %s", sc.Text())
		}
		statuses = append(statuses, e.Status)
	}
	if got := strings.Join(statuses, ","); got != "failed,failed,passed,failed,passed" {
		t.Errorf("audit statuses = %s", got)
	}
}
