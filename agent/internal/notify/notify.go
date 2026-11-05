// Package notify sends run results to webhooks configured under notify: in
// pgsafe.yaml (self-hosted alerting; the hosted control plane adds Slack,
// LINE and email in Phase 4). Payloads carry metadata only.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/redact"
)

// Event classes usable in notify[].on.
const (
	OnFailure = "failure" // failed or error
	OnBlocked = "blocked" // masking blocked: PII needs review
	OnSuccess = "success"
)

// Event is the JSON body posted to a webhook.
type Event struct {
	Event        string    `json:"event"` // e.g. "verify.failed"
	Kind         string    `json:"kind"`  // backup | verify | mask | stage
	Database     string    `json:"database"`
	Status       string    `json:"status"` // passed | failed | blocked | error
	RunID        string    `json:"run_id"`
	BackupID     string    `json:"backup_id,omitempty"`
	Summary      string    `json:"summary,omitempty"`
	Error        string    `json:"error,omitempty"`
	Host         string    `json:"host"`
	AgentVersion string    `json:"agent_version"`
	Time         time.Time `json:"time"`
}

// Class maps a run status to an event class.
func Class(status string) string {
	switch status {
	case "passed":
		return OnSuccess
	case "blocked":
		return OnBlocked
	default:
		return OnFailure
	}
}

type hook struct {
	url string
	on  map[string]bool
}

// Notifier posts events to the configured webhooks.
type Notifier struct {
	hooks   []hook
	client  *http.Client
	log     *slog.Logger
	retries int
	backoff time.Duration
}

// New builds a notifier; hooks without a URL (unset env) are skipped with a warning.
func New(cfg []config.Notify, log *slog.Logger) *Notifier {
	n := &Notifier{client: &http.Client{Timeout: 10 * time.Second}, log: log, retries: 3, backoff: time.Second}
	for i, c := range cfg {
		if c.Type != "webhook" {
			continue
		}
		if c.URL == "" {
			log.Warn("notify webhook has no url (env not set); skipping", "index", i)
			continue
		}
		on := map[string]bool{}
		for _, o := range c.On {
			on[o] = true
		}
		if len(on) == 0 {
			on[OnFailure], on[OnBlocked] = true, true
		}
		n.hooks = append(n.hooks, hook{url: c.URL, on: on})
	}
	return n
}

// Enabled reports whether any webhook is configured.
func (n *Notifier) Enabled() bool { return len(n.hooks) > 0 }

// Send posts e to every hook subscribed to its class. Failures are logged,
// never returned: alerting must not break a run.
func (n *Notifier) Send(ctx context.Context, e Event) {
	if e.Host == "" {
		e.Host, _ = os.Hostname()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Event = e.Kind + "." + e.Status
	e.Error = redact.String(e.Error)
	body, err := json.Marshal(e)
	if err != nil {
		return
	}
	class := Class(e.Status)
	for _, h := range n.hooks {
		if !h.on[class] {
			continue
		}
		if err := n.post(ctx, h.url, body, e.AgentVersion); err != nil {
			n.log.Warn("webhook failed", "url", redact.URL(h.url), "event", e.Event, "err", redact.String(err.Error()))
		}
	}
}

func (n *Notifier) post(ctx context.Context, url string, body []byte, version string) error {
	var last error
	for attempt := 0; attempt < n.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(n.backoff * time.Duration(1<<(attempt-1))):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "pgsafe-agent/"+version)
		resp, err := n.client.Do(req)
		if err != nil {
			last = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		last = fmt.Errorf("HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return last // a client error will not fix itself
		}
	}
	return last
}
