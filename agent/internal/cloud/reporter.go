package cloud

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/mask"
	"github.com/desnarong/pgsafe/agent/internal/ops"
	"github.com/desnarong/pgsafe/agent/internal/redact"
	"github.com/desnarong/pgsafe/agent/internal/scan"
	"github.com/desnarong/pgsafe/shared/apitypes"
)

// Reporter sends run metadata to the control plane through the outbox.
// It implements ops.Reporter and never fails or slows a run noticeably.
type Reporter struct {
	client *Client
	outbox *Outbox
	log    *slog.Logger
}

func NewReporter(c *Client, stateDir string, log *slog.Logger) *Reporter {
	return &Reporter{client: c, outbox: NewOutbox(stateDir), log: log}
}

var (
	// PostgreSQL messages can quote data: `invalid input syntax for type
	// integer: "abc"` or `Key (email)=(a@b.c) already exists`. Strip those.
	quotedValue = regexp.MustCompile(`(?i)((?:syntax|value|input)[^"\n]{0,60}:\s*)"[^"\n]*"`)
	keyValue    = regexp.MustCompile(`\(([^()\n]*)\)=\([^()\n]*\)`)
)

// SafeText removes credentials and quoted data values from a message.
func SafeText(s string) string {
	s = redact.String(s)
	s = quotedValue.ReplaceAllString(s, `$1"…"`)
	s = keyValue.ReplaceAllString(s, `($1)=(…)`)
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s
}

func (r *Reporter) enqueue(method, path string, body any) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.outbox.Enqueue(ctx, method, path, body); err != nil {
		r.log.Warn("could not queue a report for the control plane", "err", err)
	}
}

// Flush tries to deliver queued reports now (bounded).
func (r *Reporter) Flush() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sent, dropped, pending, err := r.outbox.Flush(ctx, r.client)
	if dropped > 0 {
		r.log.Warn("control plane rejected reports; dropped", "count", dropped)
	}
	if err != nil {
		r.log.Debug("control plane unavailable; reports stay queued", "pending", pending, "sent", sent, "err", err)
	}
}

func runReport(o *ops.Outcome, status string) apitypes.RunReport {
	rep := apitypes.RunReport{ID: o.RunID, Database: o.Database, Kind: o.Kind, Status: status, Trigger: o.Trigger,
		CommandID: o.CommandID, BackupID: o.BackupID, Summary: SafeText(o.Summary), Error: SafeText(o.Error), StartedAt: o.Started}
	if status != "running" {
		f := o.Finished
		rep.FinishedAt = &f
		rep.DurationMS = o.Finished.Sub(o.Started).Milliseconds()
	}
	if o.Verify != nil {
		for _, c := range o.Verify.Checks {
			rep.Steps = append(rep.Steps, apitypes.Step{Name: c.Name, Status: c.Status, Detail: SafeText(c.Detail)})
		}
	}
	if o.Mask != nil && o.Mask.Report != nil {
		for _, t := range o.Mask.Report.Tables {
			rep.Steps = append(rep.Steps, apitypes.Step{Name: "mask " + t.Table, Status: "passed", Detail: t.Path})
		}
		for _, c := range o.Mask.Report.PostChecks {
			rep.Steps = append(rep.Steps, apitypes.Step{Name: c.Name, Status: c.Status, Detail: SafeText(c.Detail)})
		}
	}
	return rep
}

// Started implements ops.Reporter.
func (r *Reporter) Started(o *ops.Outcome) {
	r.enqueue(http.MethodPost, "/v1/agent/runs", runReport(o, "running"))
	go r.Flush() // the run itself must not wait for the network
}

// Finished implements ops.Reporter.
func (r *Reporter) Finished(o *ops.Outcome) {
	r.enqueue(http.MethodPatch, "/v1/agent/runs/"+o.RunID, runReport(o, o.Status))
	switch {
	case o.Backup != nil && o.Backup.Manifest != nil:
		r.enqueue(http.MethodPost, "/v1/agent/backups", backupReport(o.Backup.Manifest, nil))
	case o.Verify != nil && o.Verify.Manifest != nil:
		v := o.Verify
		r.enqueue(http.MethodPost, "/v1/agent/backups", backupReport(v.Manifest, &apitypes.Verified{
			Status: v.Status, RunID: v.RunID, At: v.FinishedAt, RestoreDurationMS: v.RestoreDurationMS}))
	case o.Mask != nil && o.Mask.Masked != nil:
		r.enqueue(http.MethodPost, "/v1/agent/backups", backupReport(o.Mask.Masked, nil))
	}
	if o.Mask != nil && o.Mask.Report != nil && o.Mask.Report.Decision != nil && len(o.Mask.Report.Decision.Blocked) > 0 {
		r.findings(o.Database, "drift", blockedFindings(o.Mask.Report.Decision.Blocked))
	}
	if o.Scan != nil {
		r.findings(o.Database, "scan", o.Scan.Findings)
	}
	r.Flush()
}

func (r *Reporter) findings(db, source string, fs []scan.Finding) {
	rep := apitypes.FindingsReport{Database: db, Source: source, Findings: []apitypes.Finding{}}
	for _, f := range fs {
		if !scan.Blocking(f.Confidence) {
			continue
		}
		af := apitypes.Finding{Table: f.Table, Column: f.Column, Detector: f.Detector, Confidence: f.Confidence, Strategy: f.Strategy, Params: f.Params}
		if len(f.JSONKeys) > 0 {
			af.Params = map[string]any{"keys": f.JSONKeys}
		}
		rep.Findings = append(rep.Findings, af)
	}
	if len(rep.Findings) > 0 {
		r.enqueue(http.MethodPost, "/v1/agent/pii-findings", rep)
	}
}

func blockedFindings(bs []mask.Blocked) []scan.Finding {
	out := make([]scan.Finding, 0, len(bs))
	for _, b := range bs {
		conf := b.Confidence
		if conf == "" {
			conf = scan.Medium
		}
		strategy := b.Strategy
		if strategy == "" {
			strategy = "hash"
		}
		out = append(out, scan.Finding{Table: b.Table, Column: b.Column, Detector: b.Detector, Confidence: conf, Strategy: strategy})
	}
	return out
}

func backupReport(m *manifest.Manifest, v *apitypes.Verified) apitypes.BackupReport {
	kind := "backup"
	if m.Kind == manifest.KindMasked {
		kind = "masked"
	}
	return apitypes.BackupReport{Database: m.Database, ID: m.BackupID, Kind: kind, SizeBytes: m.SizeBytes, SHA256: m.SHA256,
		SchemaHash: m.SchemaHash, TableCount: len(m.Tables), PGVersion: m.PGServerVersion, CreatedAt: m.CreatedAt, Verified: v}
}
