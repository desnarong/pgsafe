package mask

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/scan"
)

const existing = `version: 1
# team rules — do not lose this comment
tables:
  public.customers:
    email: { strategy: fake_email, reviewed: true }   # checked by Somsri
    phone: { strategy: hash, reviewed: true }
    address: { strategy: fake_address_th, reviewed: false }
    gone_column: { strategy: hash, reviewed: true }
  public.sessions:
    _table: { strategy: truncate }
`

func TestMergeKeepsReviewedRules(t *testing.T) {
	findings := []scan.Finding{
		{Table: "public.customers", Column: "email", Detector: "email", Confidence: "high", Strategy: "fake_email"},
		{Table: "public.customers", Column: "phone", Detector: "phone_th", Confidence: "high", Strategy: "fake_phone_th"},
		{Table: "public.customers", Column: "address", Detector: "address_th", Confidence: "high", Strategy: "fake_address_th"},
		{Table: "public.customers", Column: "citizen_id", Detector: "thai_id", Confidence: "high", Strategy: "fake_thai_id"},
		{Table: "public.customers", Column: "birth_date", Detector: "birth_date", Confidence: "high", Strategy: "date_shift", Params: map[string]any{"max_days": 180}},
		{Table: "public.orders", Column: "note", Detector: "free_text", Confidence: "low", Strategy: "redact"},
		{Table: "public.audit", Column: "payload", Detector: "json", Confidence: "high", Strategy: "json_mask", JSONKeys: map[string]string{"email": "fake_email"}},
	}
	exist := map[string]bool{"public.customers.email": true, "public.customers.phone": true, "public.customers.address": true,
		"public.customers.citizen_id": true, "public.customers.birth_date": true, "public.audit.payload": true}
	out, res, err := MergeFindings([]byte(existing), findings, exist, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "team rules — do not lose this comment") || !strings.Contains(s, "checked by Somsri") {
		t.Errorf("comments lost:\n%s", s)
	}
	r, err := ParseRules(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Tables["public.customers"]["phone"]; got.Strategy != "hash" || !got.Reviewed {
		t.Errorf("reviewed rule changed: %+v", got)
	}
	if got := r.Tables["public.customers"]["citizen_id"]; got.Strategy != "fake_thai_id" || got.Reviewed || got.Confidence != "high" {
		t.Errorf("new rule: %+v", got)
	}
	if got := r.Tables["public.customers"]["birth_date"]; got.MaxDays != 180 {
		t.Errorf("date_shift params: %+v", got)
	}
	if got := r.Tables["public.audit"]["payload"]; got.Keys["email"] != "fake_email" {
		t.Errorf("json_mask keys: %+v", got)
	}
	if r.Has("public.orders", "note") {
		t.Error("low-confidence finding must not be written")
	}
	want := "added=[public.customers.citizen_id public.customers.birth_date public.audit.payload] updated=[public.customers.address] kept=[public.customers.email public.customers.phone] stale=[public.customers.gone_column]"
	got := "added=" + fmtList(res.Added) + " updated=" + fmtList(res.Updated) + " kept=" + fmtList(res.Kept) + " stale=" + fmtList(res.Stale)
	if got != want {
		t.Errorf("merge result\n got %s\nwant %s", got, want)
	}
	if u := r.Unreviewed(); len(u) != 4 {
		t.Errorf("unreviewed = %v", u)
	}
	// Merging again is stable.
	out2, _, err := MergeFindings(out, findings, exist, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil || string(out2) != string(out) {
		t.Errorf("merge not idempotent:\n%s\n---\n%s", out, out2)
	}
}

func fmtList(s []string) string { return "[" + strings.Join(s, " ") + "]" }

func TestMergeIntoEmpty(t *testing.T) {
	out, res, err := MergeFindings(nil, []scan.Finding{{Table: "public.t", Column: "email", Detector: "email", Confidence: "medium", Strategy: "fake_email"}}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || !strings.Contains(string(out), "version: 1") || !strings.Contains(string(out), "reviewed: false") {
		t.Fatalf("out:\n%s", out)
	}
}

func TestRulesValidation(t *testing.T) {
	bad := map[string]string{
		"unknown strategy": "version: 1\ntables:\n  public.t:\n    c: { strategy: shred, reviewed: true }\n",
		"unqualified":      "version: 1\ntables:\n  t:\n    c: { strategy: hash, reviewed: true }\n",
		"static no value":  "version: 1\ntables:\n  public.t:\n    c: { strategy: static, reviewed: true }\n",
		"sql no expr":      "version: 1\ntables:\n  public.t:\n    c: { strategy: sql, reviewed: true }\n",
		"noise no pct":     "version: 1\ntables:\n  public.t:\n    c: { strategy: number_noise, reviewed: true }\n",
		"truncate column":  "version: 1\ntables:\n  public.t:\n    c: { strategy: truncate, reviewed: true }\n",
		"bad json key":     "version: 1\ntables:\n  public.t:\n    c: { strategy: json_mask, keys: { a: sql }, reviewed: true }\n",
		"bad part":         "version: 1\ntables:\n  public.t:\n    c: { strategy: fake_name_th, part: middle, reviewed: true }\n",
		"typo field":       "version: 1\ntables:\n  public.t:\n    c: { strategy: hash, reviwed: true }\n",
	}
	for name, y := range bad {
		if _, err := ParseRules([]byte(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ParseRules([]byte("")); err != nil {
		t.Errorf("empty rules: %v", err)
	}
}

func TestExampleRulesParse(t *testing.T) {
	data, err := os.ReadFile("../../../pgsafe.masking.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRules(data)
	if err != nil {
		t.Fatalf("pgsafe.masking.example.yaml: %v", err)
	}
	if len(r.Unreviewed()) != 0 {
		t.Errorf("example has unreviewed rules: %v", r.Unreviewed())
	}
}

func TestApplyCloudRules(t *testing.T) {
	data := []byte(`version: 1
# keep me
tables:
  public.customers:
    email: {strategy: fake_email, reviewed: false, detector: email, confidence: high}
    tier: {strategy: keep, reviewed: true}
`)
	out, n, err := ApplyCloudRules(data, []CloudRule{
		{Table: "public.customers", Column: "email", Strategy: "fake_email"},
		{Table: "public.customers", Column: "birth_date", Strategy: "date_shift", Params: map[string]any{"max_days": float64(30)}},
		{Table: "public.payments", Column: "card_last4", Strategy: "static", Params: map[string]any{"value": "0000"}},
	})
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	r, err := ParseRules(out)
	if err != nil {
		t.Fatal(err)
	}
	if u := r.Unreviewed(); len(u) != 0 {
		t.Fatalf("still unreviewed: %v\n%s", u, out)
	}
	if got := r.Tables["public.customers"]["birth_date"]; got.MaxDays != 30 {
		t.Errorf("params lost: %+v", got)
	}
	if !strings.Contains(string(out), "keep me") || r.Tables["public.customers"]["tier"].Strategy != "keep" {
		t.Errorf("unrelated content changed:\n%s", out)
	}
	again, n2, _ := ApplyCloudRules(out, []CloudRule{{Table: "public.customers", Column: "email", Strategy: "fake_email"}})
	if n2 != 0 || string(again) != string(out) {
		t.Errorf("re-applying the same rule changed the file (n=%d)", n2)
	}
	if _, _, err := ApplyCloudRules(out, []CloudRule{{Table: "public.t", Column: "c", Strategy: "shred"}}); err == nil {
		t.Error("invalid strategy from cloud must be rejected")
	}
}
