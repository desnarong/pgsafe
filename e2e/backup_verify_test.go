//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

const verifyChecks = `
verify:
  checks:
    - type: sql
      name: has_recent_orders
      query: "select count(*) > 0 from orders where created_at > timestamptz '2025-12-01'"
`

// Backup → verify on PostgreSQL 14, 16 and 18 with age encryption and the docker runtime.
func TestBackupVerifyAllVersions(t *testing.T) {
	ws := newWorkspace(t, sourceDBs(), "age", verifyChecks)

	var b backupJSON
	ws.runJSON(&b, 0, "backup")
	if len(b.Backups) != len(sources) {
		t.Fatalf("got %d backups, want %d", len(b.Backups), len(sources))
	}
	for _, bk := range b.Backups {
		if bk.Status != "passed" || bk.Manifest == nil {
			t.Fatalf("%s: backup %s: %s", bk.Database, bk.Status, bk.Error)
		}
		checkManifest(t, bk.Database, bk.Manifest)
	}

	var v verifyJSON
	ws.runJSON(&v, 0, "verify")
	for _, ver := range v.Verifications {
		r := ver.Report
		if ver.Status != "passed" || r == nil {
			t.Fatalf("%s: verify %s: %s %+v", ver.Database, ver.Status, ver.Error, r)
		}
		if r.TablesOK != 7 || r.TablesTotal != 7 || r.RestoreDurationMS <= 0 {
			t.Errorf("%s: tables %d/%d, restore %dms", ver.Database, r.TablesOK, r.TablesTotal, r.RestoreDurationMS)
		}
		for _, c := range []string{"checksum", "decrypt", "restore", "tables_present", "row_counts", "non_empty", "schema_hash", "sql:has_recent_orders"} {
			if s := r.check(c); s != "passed" {
				t.Errorf("%s: check %s = %s", ver.Database, c, s)
			}
		}
	}
	assertNoLeftovers(t)

	var lb struct {
		Backups []struct {
			Database       string `json:"database"`
			VerifiedStatus string `json:"verified_status"`
		} `json:"backups"`
	}
	ws.runJSON(&lb, 0, "list", "backups")
	if len(lb.Backups) != len(sources) {
		t.Fatalf("list backups: %d rows", len(lb.Backups))
	}
	for _, r := range lb.Backups {
		if r.VerifiedStatus != "passed" {
			t.Errorf("list backups: %s verified_status = %q", r.Database, r.VerifiedStatus)
		}
	}
	var lr struct {
		Runs []struct{ Kind, Status string } `json:"runs"`
	}
	ws.runJSON(&lr, 0, "list", "runs")
	if len(lr.Runs) != 2*len(sources) {
		t.Errorf("list runs: %d runs, want %d", len(lr.Runs), 2*len(sources))
	}

	// The text output carries the dashboard-style sentence.
	out := ws.mustRun("verify", "--db", "shop16").stdout
	if !strings.Contains(out, "restores — restore took") || !strings.Contains(out, "7/7 tables OK") {
		t.Errorf("verify text output:\n%s", out)
	}
}

func checkManifest(t *testing.T, db string, m *manifestJSON) {
	t.Helper()
	if m.Encryption != "age" || m.Object != "dump.pgc.age" || len(m.SHA256) != 64 || m.SizeBytes == 0 {
		t.Errorf("%s: manifest header %+v", db, m)
	}
	got := map[string]bool{}
	for _, tb := range m.Tables {
		got[tb.Name] = true
		switch tb.Name {
		case "sessions", "cache_pages":
			if !tb.DataExcluded || tb.Rows != 0 {
				t.Errorf("%s: %s should be data_excluded with 0 rows: %+v", db, tb.Name, tb)
			}
		default:
			if want := wantRows[tb.Name]; tb.Rows != want || !tb.RowsExact {
				t.Errorf("%s: %s rows = %d (exact %v), want %d", db, tb.Name, tb.Rows, tb.RowsExact, want)
			}
		}
	}
	if got["audit_raw_logs"] {
		t.Errorf("%s: excluded table audit_raw_logs is in the manifest", db)
	}
	if len(m.Tables) != 7 {
		t.Errorf("%s: %d tables in manifest, want 7", db, len(m.Tables))
	}
}

// The stored object must be usable without pgsafe: standard age + pg_restore.
func TestBackupRestorableWithStandardTools(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "age", "")
	var b backupJSON
	ws.runJSON(&b, 0, "backup")
	m := b.Backups[0].Manifest

	obj := ws.getObject("backups/shop16/" + m.BackupID + "/" + m.Object)
	sum := sha256.Sum256(obj)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		t.Fatal("stored object sha256 does not match manifest (sha256sum would disagree)")
	}
	keyFile, err := os.Open(filepath.Join(ws.dir, "keys", "backup.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	ids, err := age.ParseIdentities(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(obj), ids...)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "run", "--rm", "-i", "postgres:16", "pg_restore", "--list")
	cmd.Stdin = bytes.NewReader(plain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pg_restore --list: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "TABLE DATA public customers") {
		t.Fatalf("pg_restore --list does not show customers data:\n%s", out)
	}
}

// Server runtime: a temporary database on an existing server, dropped afterwards.
// Also covers unencrypted backups.
func TestVerifyServerRuntime(t *testing.T) {
	staging := env("STAGING_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5433/shop_staging?sslmode=disable")
	ws := newWorkspace(t, sourceDBs()[1:2], "none", "verify:\n  runtime: server\n  server_url: ${E2E_SCRATCH_URL}\n")
	ws.env = append(ws.env, "E2E_SCRATCH_URL="+staging)

	var b backupJSON
	ws.runJSON(&b, 0, "backup")
	if m := b.Backups[0].Manifest; m.Encryption != "none" || m.Object != "dump.pgc" {
		t.Fatalf("unencrypted manifest: %+v", m)
	}
	var v verifyJSON
	ws.runJSON(&v, 0, "verify")
	if r := v.Verifications[0].Report; v.Verifications[0].Status != "passed" || r.TablesOK != 7 {
		t.Fatalf("verify: %+v", v.Verifications[0])
	}
	if r := v.Verifications[0].Report; r.check("decrypt") != "absent" {
		t.Error("unencrypted backup should have no decrypt check")
	}

	conn := connect(t, staging)
	var n int
	if err := conn.QueryRow(context.Background(), "select count(*) from pg_database where datname like 'pgsafe_verify_%'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d scratch databases left on the server", n)
	}
	assertNoLeftovers(t)
}

// Broken backups must fail verification at the right check, with exit code 1.
func TestVerifyDetectsBrokenBackups(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "age", "")

	newBackup := func() *manifestJSON {
		var b backupJSON
		ws.runJSON(&b, 0, "backup")
		return b.Backups[0].Manifest
	}
	dir := func(m *manifestJSON) string { return "backups/shop16/" + m.BackupID + "/" }
	verifyFails := func(t *testing.T, m *manifestJSON, wantFailed ...string) *reportJSON {
		t.Helper()
		var v verifyJSON
		ws.runJSON(&v, 1, "verify", "--backup", m.BackupID)
		r := v.Verifications[0].Report
		if r == nil || r.Status != "failed" {
			t.Fatalf("verify status = %+v", v.Verifications[0])
		}
		for _, c := range wantFailed {
			if s := r.check(c); s != "failed" {
				t.Errorf("check %s = %s, want failed (%+v)", c, s, r.Checks)
			}
		}
		assertNoLeftovers(t)
		return r
	}
	rewriteManifest := func(m *manifestJSON, edit func(map[string]any)) {
		var raw map[string]any
		if err := json.Unmarshal(ws.getObject(dir(m)+"manifest.json"), &raw); err != nil {
			t.Fatal(err)
		}
		edit(raw)
		data, _ := json.Marshal(raw)
		ws.putObject(dir(m)+"manifest.json", data)
	}

	t.Run("truncated object fails checksum", func(t *testing.T) {
		m := newBackup()
		obj := ws.getObject(dir(m) + m.Object)
		ws.putObject(dir(m)+m.Object, obj[:len(obj)/2])
		r := verifyFails(t, m, "checksum")
		if r.check("restore") != "absent" {
			t.Error("must stop before restoring a corrupt object")
		}
	})

	t.Run("truncated object with matching checksum fails decrypt", func(t *testing.T) {
		m := newBackup()
		half := ws.getObject(dir(m) + m.Object)
		half = half[:len(half)/2]
		ws.putObject(dir(m)+m.Object, half)
		sum := sha256.Sum256(half)
		rewriteManifest(m, func(raw map[string]any) {
			raw["sha256"] = hex.EncodeToString(sum[:])
			raw["size_bytes"] = len(half)
		})
		verifyFails(t, m, "decrypt")
	})

	t.Run("missing table and wrong row count fail data checks", func(t *testing.T) {
		m := newBackup()
		rewriteManifest(m, func(raw map[string]any) {
			tables := raw["tables"].([]any)
			for _, tb := range tables {
				if tbm := tb.(map[string]any); tbm["name"] == "customers" {
					tbm["rows"] = tbm["rows"].(float64) + 1
				}
			}
			raw["tables"] = append(tables, map[string]any{"schema": "public", "name": "ghost", "rows": 5, "rows_exact": true})
		})
		r := verifyFails(t, m, "tables_present", "row_counts")
		if r.check("restore") != "passed" {
			t.Errorf("restore itself should pass: %s", r.check("restore"))
		}
	})

	t.Run("custom sql check returning false fails", func(t *testing.T) {
		ws2 := newWorkspace(t, sourceDBs()[1:2], "age", "verify:\n  checks:\n    - type: sql\n      name: never\n      query: \"select false\"\n")
		var b backupJSON
		ws2.runJSON(&b, 0, "backup")
		var v verifyJSON
		ws2.runJSON(&v, 1, "verify")
		if r := v.Verifications[0].Report; r.check("sql:never") != "failed" || r.check("row_counts") != "passed" {
			t.Fatalf("checks: %+v", r.Checks)
		}
		assertNoLeftovers(t)
	})

	// verify.json is written for failed runs too.
	var lb struct {
		Backups []struct {
			VerifiedStatus string `json:"verified_status"`
		} `json:"backups"`
	}
	ws.runJSON(&lb, 0, "list", "backups")
	failed := 0
	for _, r := range lb.Backups {
		if r.VerifiedStatus == "failed" {
			failed++
		}
	}
	if failed != 3 {
		t.Errorf("list backups shows %d failed verifications, want 3", failed)
	}
}

// Retention deletes old pgsafe backups but never objects without a manifest.
func TestRetention(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "none", "retention:\n  daily: 1\n  weekly: 0\n  monthly: 0\n")
	var first backupJSON
	ws.runJSON(&first, 0, "backup")
	m := first.Backups[0].Manifest
	oldDir := "backups/shop16/" + m.BackupID + "/"

	// Age the first backup by 10 days (rewrite created_at).
	var raw map[string]any
	json.Unmarshal(ws.getObject(oldDir+"manifest.json"), &raw)
	raw["created_at"] = time.Now().UTC().AddDate(0, 0, -10).Format(time.RFC3339)
	data, _ := json.Marshal(raw)
	ws.putObject(oldDir+"manifest.json", data)
	// Something pgsafe did not create, in its directory tree.
	ws.putObject("backups/shop16/not-pgsafe/notes.txt", []byte("keep me"))

	var second backupJSON
	ws.runJSON(&second, 0, "backup")
	if got := second.Backups[0].Removed; len(got) != 1 || got[0] != m.BackupID {
		t.Fatalf("removed_by_retention = %v, want [%s]", got, m.BackupID)
	}
	keys := strings.Join(ws.listKeys(), "\n")
	if strings.Contains(keys, m.BackupID) {
		t.Errorf("old backup objects still present:\n%s", keys)
	}
	if !strings.Contains(keys, "backups/shop16/not-pgsafe/notes.txt") {
		t.Errorf("retention deleted an object without a pgsafe manifest:\n%s", keys)
	}
	if !strings.Contains(keys, second.Backups[0].BackupID+"/manifest.json") {
		t.Errorf("new backup missing:\n%s", keys)
	}
}

// Config errors exit 2; credentials written in the file are rejected.
func TestConfigErrors(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "none", "")
	ws.env = append(ws.env, "E2E_PG16_URL=") // unset the database URL
	if r := ws.run("backup"); r.code != 2 || !strings.Contains(r.stderr, "E2E_PG16_URL") {
		t.Fatalf("missing env: exit %d, stderr %s", r.code, r.stderr)
	}

	cfgPath := filepath.Join(ws.dir, "pgsafe.yaml")
	data, _ := os.ReadFile(cfgPath)
	bad := strings.Replace(string(data), "${E2E_PG16_URL}", "postgres://pgsafe:hunter2@localhost:5416/shop", 1)
	os.WriteFile(cfgPath, []byte(bad), 0o644)
	r := ws.run("backup")
	if r.code != 2 || !strings.Contains(r.stderr, "credentials must not be written") || strings.Contains(r.stderr, "hunter2") {
		t.Fatalf("literal credentials: exit %d, stderr %s", r.code, r.stderr)
	}
}
