//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
)

const maskSalt = "e2e-mask-salt-0123456789abcdef"

func stagingAdminURL() string {
	return env("STAGING_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5433/shop_staging?sslmode=disable")
}

// stagingURL returns a URL for database name on the dev staging server.
func stagingURL(name string) string {
	return strings.Replace(stagingAdminURL(), "/shop_staging?", "/"+name+"?", 1)
}

func execStaging(t *testing.T, db, sql string) {
	t.Helper()
	conn := connect(t, stagingURL(db))
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func dropStagingDB(t *testing.T, name string) {
	conn, err := pgx.Connect(context.Background(), stagingAdminURL())
	if err != nil {
		return
	}
	defer conn.Close(context.Background())
	conn.Exec(context.Background(), "drop database if exists "+pgx.Identifier{name}.Sanitize()+" with (force)")
}

// maskWorkspace is a pg16 workspace with masking and a staging database target.
func maskWorkspace(t *testing.T, stagingDB string, extra string) *workspace {
	t.Helper()
	cfg := `masking:
  rules_file: ./pgsafe.masking.yaml
  salt: ${E2E_MASK_SALT}
  large_table_rows: 10000
staging:
  encryption:
    type: age
    recipients_file: ./keys/dev.pub
    identity_file: ${E2E_DEV_KEY}
  targets:
    - type: database
      url: ${E2E_STAGING_URL}
      mode: replace
      preserve_tables: [feature_flags]
    - type: s3
      prefix: masked/
` + extra
	ws := newWorkspace(t, sourceDBs()[1:2], "age", cfg)
	devKey := filepath.Join(ws.dir, "keys", "dev.key")
	ws.env = append(ws.env, "E2E_MASK_SALT="+maskSalt, "E2E_STAGING_URL="+stagingURL(stagingDB), "E2E_DEV_KEY="+devKey)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(devKey, []byte(id.String()+"\n"), 0o600)
	os.WriteFile(filepath.Join(ws.dir, "keys", "dev.pub"), []byte(id.Recipient().String()+"\n"), 0o644)
	t.Cleanup(func() { dropStagingDB(t, stagingDB) })
	return ws
}

// reviewRules marks every rule reviewed and adds the hand-written ones a
// team would add (truncate sessions, static card_last4).
func reviewRules(t *testing.T, ws *workspace) {
	t.Helper()
	p := filepath.Join(ws.dir, "pgsafe.masking.yaml")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(data), "reviewed: false", "reviewed: true")
	s = strings.Replace(s, "  public.payments:\n", "  public.payments:\n    card_last4: {strategy: static, value: \"0000\", reviewed: true}\n", 1)
	s += "  public.sessions:\n    _table: {strategy: truncate}\n"
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

type scanJSON struct {
	Scans []struct {
		Findings []struct {
			Table, Column, Detector, Confidence, Strategy string
		} `json:"findings"`
		Rules struct {
			Added []string `json:"added"`
		} `json:"rules"`
	} `json:"scans"`
}

// Golden: scanning the seed yields exactly the expected findings.
func TestScanGolden(t *testing.T) {
	ws := newWorkspace(t, sourceDBs()[1:2], "age", "")
	ws.mustRun("backup")
	var s scanJSON
	ws.runJSON(&s, 0, "scan", "--no-write")
	var got []string
	for _, f := range s.Scans[0].Findings {
		got = append(got, fmt.Sprintf("%s.%s %s %s %s", f.Table, f.Column, f.Detector, f.Confidence, f.Strategy))
	}
	sort.Strings(got)
	golden := filepath.Join("testdata", "scan_golden.txt")
	if os.Getenv("PGSAFE_UPDATE_GOLDEN") == "1" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(golden, []byte(strings.Join(got, "\n")+"\n"), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with PGSAFE_UPDATE_GOLDEN=1 to create it)", err)
	}
	if strings.TrimSpace(string(want)) != strings.Join(got, "\n") {
		t.Fatalf("scan findings differ from %s\n got:\n%s\nwant:\n%s", golden, strings.Join(got, "\n"), want)
	}
	if _, err := os.Stat(filepath.Join(ws.dir, "pgsafe.masking.yaml")); err == nil {
		t.Error("--no-write must not create the rules file")
	}
}

type stageJSON struct {
	Stages []struct {
		Status   string `json:"status"`
		MaskedID string `json:"masked_id"`
		Remasked bool   `json:"remasked"`
		Error    string `json:"error"`
		Targets  []struct {
			Type   string `json:"type"`
			Result *struct {
				Replaced  bool     `json:"replaced"`
				Preserved []string `json:"preserved_tables"`
			} `json:"result"`
		} `json:"targets"`
	} `json:"stages"`
}

type maskReport struct {
	Tables []struct {
		Table, Path string
		Rows        int64
	} `json:"tables"`
	FKsValidated int `json:"fks_validated"`
}

type customer struct {
	id                                                              int
	email, fullName, firstName, lastName, phone, citizenID, address string
	notes                                                           *string
	birth                                                           time.Time
}

func loadCustomers(t *testing.T, url string) map[int]customer {
	t.Helper()
	conn := connect(t, url)
	rows, err := conn.Query(context.Background(), `select id, email, full_name, first_name, last_name, phone, citizen_id, address, notes, birth_date from customers`)
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]customer{}
	for rows.Next() {
		var c customer
		if err := rows.Scan(&c.id, &c.email, &c.fullName, &c.firstName, &c.lastName, &c.phone, &c.citizenID, &c.address, &c.notes, &c.birth); err != nil {
			t.Fatal(err)
		}
		out[c.id] = c
	}
	return out
}

var (
	emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	longDigitRe = regexp.MustCompile(`\d[\d\s-]{7,}\d`)
)

func thaiIDValid(d string) bool {
	if len(d) != 13 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(d[i]-'0') * (13 - i)
	}
	return (11-sum%11)%10 == int(d[12]-'0')
}

// The whole Phase 2 flow: scan → blocked → review → stage (mask + deliver) → pull.
func TestMaskStagePull(t *testing.T) {
	stagingDB := "e2e_stage_" + randHex(3)
	ws := maskWorkspace(t, stagingDB, "")
	ws.mustRun("backup")

	// A staging database already in use, with a table the dev team owns.
	admin := connect(t, stagingAdminURL())
	if _, err := admin.Exec(context.Background(), "create database "+stagingDB); err != nil {
		t.Fatal(err)
	}
	execStaging(t, stagingDB, "create table feature_flags (name text primary key, enabled boolean); insert into feature_flags values ('new_checkout', true), ('dark_mode', false)")

	var s scanJSON
	ws.runJSON(&s, 0, "scan")
	if len(s.Scans[0].Rules.Added) < 12 {
		t.Fatalf("scan added only %v", s.Scans[0].Rules.Added)
	}

	// Fail closed: nothing reviewed yet.
	var blocked stageJSON
	ws.runJSON(&blocked, 3, "stage")
	if blocked.Stages[0].Status != "blocked" {
		t.Fatalf("stage before review: %+v", blocked.Stages[0])
	}
	var flagsBefore int
	connect(t, stagingURL(stagingDB)).QueryRow(context.Background(), "select count(*) from feature_flags").Scan(&flagsBefore)
	if flagsBefore != 2 {
		t.Fatal("a blocked stage must leave the staging database alone")
	}
	reviewRules(t, ws)

	var st stageJSON
	ws.runJSON(&st, 0, "stage")
	sg := st.Stages[0]
	if sg.Status != "passed" || !sg.Remasked || len(sg.Targets) != 2 {
		t.Fatalf("stage: %+v", sg)
	}
	if r := sg.Targets[0].Result; r == nil || !r.Replaced || len(r.Preserved) != 1 || r.Preserved[0] != "public.feature_flags" {
		t.Fatalf("database target: %+v", sg.Targets[0].Result)
	}

	var rep maskReport
	json.Unmarshal(ws.getObject("masked/shop16/"+sg.MaskedID+"/mask.json"), &rep)
	paths := map[string]string{}
	for _, tb := range rep.Tables {
		paths[tb.Table] = tb.Path
	}
	if paths["public.customers"] != "ctas" || paths["public.orders"] != "ctas" || paths["public.payments"] != "update" || paths["public.sessions"] != "truncate" {
		t.Errorf("mask paths: %v", paths)
	}
	if rep.FKsValidated < 4 {
		t.Errorf("fks validated = %d", rep.FKsValidated)
	}

	checkMasked(t, sources[1].url, stagingURL(stagingDB))

	// preserve_tables kept the dev team's data.
	var flags int
	connect(t, stagingURL(stagingDB)).QueryRow(context.Background(), "select count(*) from feature_flags").Scan(&flags)
	if flags != 2 {
		t.Errorf("feature_flags rows = %d, want 2", flags)
	}
	var leftovers int
	admin.QueryRow(context.Background(), "select count(*) from pg_database where datname like '%\\_pgsafe\\_new\\_%' or datname like '%\\_pgsafe\\_old\\_%'").Scan(&leftovers)
	if leftovers != 0 {
		t.Errorf("%d temporary databases left on the staging server", leftovers)
	}

	// Second stage reuses the masked dump (same backup, same rules).
	var again stageJSON
	ws.runJSON(&again, 0, "stage")
	if again.Stages[0].Remasked || again.Stages[0].MaskedID != sg.MaskedID {
		t.Errorf("second stage should reuse %s: %+v", sg.MaskedID, again.Stages[0])
	}

	// The masked dump is encrypted for the dev team; the backup key cannot open it.
	obj := ws.getObject("masked/shop16/" + sg.MaskedID + "/dump.pgc.age")
	bk, _ := os.Open(filepath.Join(ws.dir, "keys", "backup.key"))
	bids, _ := age.ParseIdentities(bk)
	bk.Close()
	if _, err := age.Decrypt(bytes.NewReader(obj), bids...); err == nil {
		t.Error("masked dump must not be decryptable with the production backup key")
	}

	// pull: developer restore into a fresh database.
	devDB := "e2e_dev_" + randHex(3)
	t.Cleanup(func() { dropStagingDB(t, devDB) })
	ws.mustRun("pull", "--staging", "--to", stagingURL(devDB))
	var n int
	var masked bool
	connect(t, stagingURL(devDB)).QueryRow(context.Background(), "select count(*), bool_and(email like '%@example.test') from customers").Scan(&n, &masked)
	if n != 20000 || !masked {
		t.Errorf("pulled db: %d customers, masked=%v", n, masked)
	}
	if r := ws.run("pull", "--staging", "--to", stagingURL(devDB)); r.code != 2 || !strings.Contains(r.stderr, "already exists") {
		t.Errorf("pull into existing db without --replace: exit %d %s", r.code, r.stderr)
	}
	ws.mustRun("pull", "--staging", "--to", stagingURL(devDB), "--replace")

	// Never overwrite a source database.
	if r := ws.run("pull", "--staging", "--to", sources[1].url); r.code != 2 {
		t.Errorf("pull to source: exit %d", r.code)
	}
	assertNoLeftovers(t)
}

// checkMasked compares the masked staging database with the source, row by row.
func checkMasked(t *testing.T, sourceURL, maskedURL string) {
	t.Helper()
	src := loadCustomers(t, sourceURL)
	dst := loadCustomers(t, maskedURL)
	if len(dst) != len(src) {
		t.Fatalf("masked customers = %d, source %d", len(dst), len(src))
	}
	realEmail, realName, realAddr := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range src {
		realEmail[c.email], realName[c.fullName], realAddr[c.address] = true, true, true
	}
	ids := map[string]bool{}
	sameBirth := 0
	for id, s := range src {
		d := dst[id]
		for _, pair := range [][3]string{{"email", s.email, d.email}, {"full_name", s.fullName, d.fullName}, {"phone", s.phone, d.phone},
			{"citizen_id", s.citizenID, d.citizenID}, {"address", s.address, d.address}} {
			if pair[1] == pair[2] {
				t.Fatalf("customer %d: %s unchanged", id, pair[0])
			}
		}
		if realEmail[d.email] || realName[d.fullName] || realAddr[d.address] {
			t.Fatalf("customer %d: a real value from the source appears in the masked table", id)
		}
		if !strings.HasSuffix(d.email, "@example.test") {
			t.Fatalf("customer %d: email %q", id, d.email)
		}
		if !thaiIDValid(d.citizenID) {
			t.Fatalf("customer %d: citizen_id %q fails the checksum", id, d.citizenID)
		}
		ids[d.citizenID] = true
		if strings.HasPrefix(s.phone, "+66") != strings.HasPrefix(d.phone, "+66") || len(s.phone) != len(d.phone) {
			t.Fatalf("customer %d: phone format changed %q → %q", id, s.phone, d.phone)
		}
		if s.birth.Equal(d.birth) {
			sameBirth++
		}
		if d.notes != nil && (emailRe.MatchString(*d.notes) || longDigitRe.MatchString(*d.notes)) {
			t.Fatalf("customer %d: PII left in notes %q", id, *d.notes)
		}
		if s.notes != nil && (strings.Contains(*s.notes, "@") || longDigitRe.MatchString(*s.notes)) && (d.notes == nil || !strings.Contains(*d.notes, "[REDACTED]")) {
			t.Fatalf("customer %d: notes not redacted: %v", id, d.notes)
		}
	}
	if len(ids) != len(src) {
		t.Errorf("citizen_id lost uniqueness: %d distinct of %d", len(ids), len(src))
	}
	if sameBirth > len(src)/100 {
		t.Errorf("%d birth dates not shifted", sameBirth)
	}

	conn := connect(t, maskedURL)
	ctx := context.Background()
	var badJoin, sessions, notValid, schemas int
	conn.QueryRow(ctx, "select count(*) from orders o join customers c on c.id = o.customer_id where o.customer_email <> c.email").Scan(&badJoin)
	conn.QueryRow(ctx, "select count(*) from sessions").Scan(&sessions)
	conn.QueryRow(ctx, "select count(*) from pg_constraint where contype = 'f' and not convalidated").Scan(&notValid)
	conn.QueryRow(ctx, "select count(*) from pg_namespace where nspname = 'pgsafe_mask'").Scan(&schemas)
	if badJoin != 0 {
		t.Errorf("%d orders no longer join on customer_email (masking not deterministic)", badJoin)
	}
	if sessions != 0 || notValid != 0 || schemas != 0 {
		t.Errorf("sessions=%d not-valid FKs=%d pgsafe_mask schemas=%d", sessions, notValid, schemas)
	}
	var cards, badCards int
	conn.QueryRow(ctx, "select count(*), count(*) filter (where card_last4 <> '0000') from payments where card_number is not null").Scan(&cards, &badCards)
	if cards == 0 || badCards != 0 {
		t.Errorf("payments: %d cards, %d with real last4", cards, badCards)
	}
}

// A new PII column in the source blocks staging (fail closed) with exit 3.
func TestMaskDriftBlocks(t *testing.T) {
	stagingDB := "e2e_drift_" + randHex(3)
	ws := maskWorkspace(t, stagingDB, "")
	ws.mustRun("backup")
	ws.mustRun("scan")
	reviewRules(t, ws)

	src := connect(t, sources[1].url)
	ctx := context.Background()
	if _, err := src.Exec(ctx, "alter table customers add column line_id text; update customers set line_id = '@user' || id where id % 3 = 0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Exec(context.Background(), "alter table customers drop column if exists line_id") })

	admin := connect(t, stagingAdminURL())
	admin.Exec(ctx, "create database "+stagingDB)
	execStaging(t, stagingDB, "create table marker (x int)")

	ws.mustRun("backup")
	r := ws.run("stage")
	if r.code != 3 || !strings.Contains(r.stdout+r.stderr, "public.customers.line_id") {
		t.Fatalf("stage after drift: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if r := ws.run("mask"); r.code != 3 {
		t.Fatalf("mask after drift: exit %d", r.code)
	}
	var tables []string
	rows, _ := connect(t, stagingURL(stagingDB)).Query(ctx, "select tablename from pg_tables where schemaname = 'public'")
	for rows.Next() {
		var s string
		rows.Scan(&s)
		tables = append(tables, s)
	}
	if len(tables) != 1 || tables[0] != "marker" {
		t.Errorf("staging database was modified: %v", tables)
	}
	rules, _ := os.ReadFile(filepath.Join(ws.dir, "pgsafe.masking.yaml"))
	if !regexp.MustCompile(`line_id: \{strategy: hash, reviewed: false`).Match(rules) {
		t.Errorf("drift suggestion not added to rules:\n%s", rules)
	}

	// After review it goes through.
	os.WriteFile(filepath.Join(ws.dir, "pgsafe.masking.yaml"), bytes.ReplaceAll(rules, []byte("reviewed: false"), []byte("reviewed: true")), 0o644)
	ws.mustRun("stage")
	var lineIDs int
	connect(t, stagingURL(stagingDB)).QueryRow(ctx, "select count(*) from customers where line_id like '@user%'").Scan(&lineIDs)
	if lineIDs != 0 {
		t.Errorf("%d LINE IDs left unmasked", lineIDs)
	}
	assertNoLeftovers(t)
}

// Opt-in: PGSAFE_E2E_PERF=1. A 10M-row table must take the CTAS path and mask within 5 minutes.
func TestMaskPerformance(t *testing.T) {
	if os.Getenv("PGSAFE_E2E_PERF") != "1" {
		t.Skip("set PGSAFE_E2E_PERF=1")
	}
	ctx := context.Background()
	src := connect(t, sources[1].url)
	perfDB := "perf_" + randHex(3)
	if _, err := src.Exec(ctx, "create database "+perfDB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		connect(t, sources[1].url).Exec(context.Background(), "drop database if exists "+perfDB+" with (force)")
	})
	perfURL := strings.Replace(sources[1].url, "/shop?", "/"+perfDB+"?", 1)
	if _, err := connect(t, perfURL).Exec(ctx, `
		create table people (id bigint primary key, email text not null, phone text not null, full_name text not null);
		insert into people select i, 'user' || i || '@gmail.com', '08' || lpad(i::text, 8, '0'), 'นายสมชาย ใจดี' || i from generate_series(1, 10000000) i;
		analyze people`); err != nil {
		t.Fatal(err)
	}
	ws := newWorkspace(t, []wsDB{{name: "perf", envVar: "E2E_PERF_URL", url: perfURL}}, "none", `masking:
  rules_file: ./pgsafe.masking.yaml
  salt: ${E2E_MASK_SALT}
  jobs: 4
staging:
  targets:
    - type: s3
`)
	ws.env = append(ws.env, "E2E_MASK_SALT="+maskSalt)
	os.WriteFile(filepath.Join(ws.dir, "pgsafe.masking.yaml"), []byte(`version: 1
tables:
  public.people:
    email: {strategy: fake_email, reviewed: true}
    phone: {strategy: fake_phone_th, reviewed: true}
    full_name: {strategy: fake_name_th, reviewed: true}
`), 0o644)
	ws.mustRun("backup")
	t0 := time.Now()
	var m struct {
		Masks []struct {
			Result struct {
				Masked struct{ BackupID string } `json:"masked"`
				Report struct {
					Tables []struct {
						Path       string
						DurationMS int64 `json:"duration_ms"`
					} `json:"tables"`
				} `json:"report"`
			} `json:"result"`
		} `json:"masks"`
	}
	ws.runJSON(&m, 0, "mask")
	tb := m.Masks[0].Result.Report.Tables[0]
	t.Logf("10M rows: masking %s via %s; whole mask command %s", time.Duration(tb.DurationMS)*time.Millisecond, tb.Path, time.Since(t0).Round(time.Second))
	if tb.Path != "ctas" {
		t.Errorf("path = %s, want ctas", tb.Path)
	}
	if time.Duration(tb.DurationMS)*time.Millisecond > 5*time.Minute {
		t.Errorf("masking 10M rows took %s (limit 5m)", time.Duration(tb.DurationMS)*time.Millisecond)
	}
}
