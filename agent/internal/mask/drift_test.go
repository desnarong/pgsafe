package mask

import (
	"testing"

	"github.com/desnarong/pgsafe/agent/internal/scan"
)

func TestDecide(t *testing.T) {
	rules, err := ParseRules([]byte(`version: 1
tables:
  public.customers:
    email: { strategy: fake_email, reviewed: true }
    address: { strategy: fake_address_th, reviewed: false, detector: address_th, confidence: high }
    removed: { strategy: hash, reviewed: true }
  public.sessions:
    _table: { strategy: truncate }
`))
	if err != nil {
		t.Fatal(err)
	}
	existing := map[string]bool{
		"public.customers.email": true, "public.customers.address": true, "public.customers.line_id": true,
		"public.customers.tier": true, "public.sessions.token": true,
	}
	findings := []scan.Finding{
		{Table: "public.customers", Column: "line_id", Detector: "social_id", Confidence: "medium", Strategy: "hash"},
		{Table: "public.customers", Column: "tier", Detector: "name_th", Confidence: "low", Strategy: "fake_name_th"},
		{Table: "public.sessions", Column: "token", Detector: "social_id", Confidence: "high", Strategy: "hash"},
	}

	d := Decide(rules, existing, findings, PolicyBlock)
	if len(d.Blocked) != 2 || d.Blocked[0].Key() != "public.customers.address" || d.Blocked[1].Key() != "public.customers.line_id" {
		t.Fatalf("block: %+v", d.Blocked)
	}
	if d.Blocked[1].Reason != "new column without a rule" || d.Blocked[0].Reason != "unreviewed rule" {
		t.Errorf("reasons: %+v", d.Blocked)
	}
	if len(d.Stale) != 1 || d.Stale[0] != "public.customers.removed" {
		t.Errorf("stale: %v", d.Stale)
	}

	d = Decide(rules, existing, findings, PolicyMaskDefault)
	if len(d.Blocked) != 0 || d.Effective["public.customers"]["line_id"].Strategy != "hash" || d.Effective["public.customers"]["address"].Strategy != "fake_address_th" {
		t.Fatalf("mask_default: %+v %+v", d.Blocked, d.Effective)
	}
	if _, masked := d.Effective["public.customers"]["tier"]; masked {
		t.Error("low-confidence finding must not be auto-masked")
	}

	d = Decide(rules, existing, findings, PolicyWarn)
	if len(d.Blocked) != 0 || len(d.Warnings) != 2 {
		t.Fatalf("warn: %+v %v", d.Blocked, d.Warnings)
	}
	if _, masked := d.Effective["public.customers"]["line_id"]; masked {
		t.Error("warn must not invent rules")
	}
	if d.Effective["public.sessions"][TableKey].Strategy != "truncate" {
		t.Error("table rule missing")
	}
}
