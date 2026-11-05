package config

import (
	"os"
	"strings"
	"testing"
)

const sample = `
version: 1
databases:
  - name: app-prod
    url: ${PROD_DATABASE_URL}
    exclude_tables: [audit_raw_logs]
    exclude_table_data: [sessions, cache_*]
storage:
  type: s3
  bucket: acme-pg-backups
  prefix: app-prod
encryption:
  type: age
  recipients_file: ./keys/backup.pub
retention: { daily: 7, weekly: 4, monthly: 6 }
schedule:
  backup: "0 2 * * *"
  verify: after_backup
  stage: after_verify
verify:
  runtime: docker
  server_url: ${SCRATCH_DATABASE_URL}
  row_count:
    exact_below_rows: 5_000_000
    estimate_tolerance_pct: 2
  checks:
    - type: sql
      name: has_recent_orders
      query: "select true"
masking:
  rules_file: ./pgsafe.masking.yaml
  salt: ${PGSAFE_MASK_SALT}
  on_unreviewed_pii: block
staging:
  targets:
    - type: database
      url: ${STAGING_DATABASE_URL}
      mode: replace
    - type: s3
      prefix: masked/
notify:
  - type: webhook
    url: ${ALERT_WEBHOOK_URL}
    on: [failure]
cloud:
  enabled: false
`

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestParseDesignDocSample(t *testing.T) {
	cfg, err := Parse([]byte(sample), env(map[string]string{"PROD_DATABASE_URL": "postgres://u:p@db/app"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Databases[0].URL; got != "postgres://u:p@db/app" {
		t.Errorf("url not expanded: %q", got)
	}
	if cfg.Verify.RowCount.ExactBelowRows != 5_000_000 {
		t.Errorf("exact_below_rows = %d", cfg.Verify.RowCount.ExactBelowRows)
	}
	if cfg.Storage.NormPrefix() != "app-prod/" {
		t.Errorf("prefix = %q", cfg.Storage.NormPrefix())
	}
	if cfg.PGClient != "auto" || cfg.StateDir != ".pgsafe" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestMissingEnvIsReportedOnlyWhenRequired(t *testing.T) {
	cfg, err := Parse([]byte(sample), env(nil))
	if err != nil {
		t.Fatalf("missing env must not fail Parse: %v", err)
	}
	err = cfg.Require(map[string]string{cfg.DatabaseURLField("app-prod"): cfg.Databases[0].URL})
	if err == nil || !strings.Contains(err.Error(), "PROD_DATABASE_URL") {
		t.Fatalf("Require error = %v, want mention of PROD_DATABASE_URL", err)
	}
}

func TestRejectsLiteralCredentials(t *testing.T) {
	for _, url := range []string{
		"postgres://app:hunter2@db/app",
		"host=db user=app password=hunter2",
	} {
		y := strings.Replace(sample, "${PROD_DATABASE_URL}", `"`+url+`"`, 1)
		_, err := Parse([]byte(y), env(nil))
		if err == nil || !strings.Contains(err.Error(), "credentials must not be written") {
			t.Errorf("%s: err = %v", url, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error leaks password: %v", err)
		}
	}
	// A literal URL without a password is fine (e.g. peer/IAM auth).
	y := strings.Replace(sample, "${PROD_DATABASE_URL}", "postgres://app@db/app", 1)
	if _, err := Parse([]byte(y), env(nil)); err != nil {
		t.Errorf("password-less literal url rejected: %v", err)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	y := strings.Replace(sample, "retention:", "retension:", 1)
	if _, err := Parse([]byte(y), env(nil)); err == nil {
		t.Fatal("typo in key should fail")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"bad version":   strings.Replace(sample, "version: 1", "version: 2", 1),
		"bad runtime":   strings.Replace(sample, "runtime: docker", "runtime: k8s", 1),
		"bad cron":      strings.Replace(sample, `"0 2 * * *"`, `"every night"`, 1),
		"no bucket":     strings.Replace(sample, "bucket: acme-pg-backups", "bucket: ''", 1),
		"bad name":      strings.Replace(sample, "name: app-prod", "name: App Prod", 1),
		"no recipients": strings.Replace(sample, "recipients_file: ./keys/backup.pub", "recipients_file: ''", 1),
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y), env(nil)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestExpandedValueStaysString(t *testing.T) {
	y := strings.Replace(sample, "prefix: app-prod", "prefix: ${PREFIX}", 1)
	cfg, err := Parse([]byte(y), env(map[string]string{"PREFIX": "123"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Prefix != "123" {
		t.Fatalf("prefix = %q", cfg.Storage.Prefix)
	}
}

func TestRequireSalt(t *testing.T) {
	cfg, err := Parse([]byte(sample), env(map[string]string{"PGSAFE_MASK_SALT": "short"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.RequireSalt(); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short salt: %v", err)
	}
	cfg, _ = Parse([]byte(sample), env(nil))
	if err := cfg.RequireSalt(); err == nil || !strings.Contains(err.Error(), "PGSAFE_MASK_SALT") {
		t.Fatalf("missing salt: %v", err)
	}
	cfg, _ = Parse([]byte(sample), env(map[string]string{"PGSAFE_MASK_SALT": "0123456789abcdef0123"}))
	if err := cfg.RequireSalt(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingKeyMustDifferFromBackupKey(t *testing.T) {
	y := strings.Replace(sample, "staging:\n", "staging:\n  encryption:\n    type: age\n    recipients_file: ./keys/backup.pub\n", 1)
	if _, err := Parse([]byte(y), env(nil)); err == nil || !strings.Contains(err.Error(), "separate key") {
		t.Fatalf("err = %v", err)
	}
	y = strings.Replace(sample, "staging:\n", "staging:\n  encryption:\n    type: age\n    recipients_file: ./keys/dev.pub\n", 1)
	if _, err := Parse([]byte(y), env(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile("../../../pgsafe.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, env(nil)); err != nil {
		t.Fatalf("pgsafe.example.yaml: %v", err)
	}
}

func TestNotifyValidation(t *testing.T) {
	for _, bad := range []string{"type: slack\n    url: x", "type: webhook\n    url: x\n    on: [sometimes]"} {
		y := strings.Replace(sample, "type: webhook\n    url: ${ALERT_WEBHOOK_URL}\n    on: [failure]", bad, 1)
		if _, err := Parse([]byte(y), env(nil)); err == nil {
			t.Errorf("notify %q should be rejected", bad)
		}
	}
	y := strings.Replace(sample, `backup: "0 2 * * *"`, `backup: "@every 6h"`, 1)
	if _, err := Parse([]byte(y), env(nil)); err != nil {
		t.Errorf("@every schedule: %v", err)
	}
}
