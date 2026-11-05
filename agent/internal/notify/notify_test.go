package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/config"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSendRetriesAndFilters(t *testing.T) {
	var calls atomic.Int32
	var got Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "pgsafe-agent/") {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
	}))
	defer srv.Close()

	n := New([]config.Notify{{Type: "webhook", URL: srv.URL, On: []string{"failure"}}}, quiet())
	n.backoff = time.Millisecond
	n.Send(context.Background(), Event{Kind: "verify", Status: "passed", Database: "shop"})
	if calls.Load() != 0 {
		t.Fatal("success event sent to a failure-only hook")
	}
	n.Send(context.Background(), Event{Kind: "verify", Status: "failed", Database: "shop", AgentVersion: "1.0",
		Error: "connect postgres://app:hunter22@db/x failed"})
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3 (2 failures + success)", calls.Load())
	}
	if got.Event != "verify.failed" || got.Database != "shop" || got.Host == "" || got.Time.IsZero() {
		t.Fatalf("payload %+v", got)
	}
	if strings.Contains(got.Error, "hunter22") {
		t.Fatalf("secret leaked: %s", got.Error)
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	n := New([]config.Notify{{Type: "webhook", URL: srv.URL}}, quiet())
	n.backoff = time.Millisecond
	n.Send(context.Background(), Event{Kind: "backup", Status: "error"})
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestDefaultsAndClass(t *testing.T) {
	n := New([]config.Notify{{Type: "webhook", URL: "http://x"}, {Type: "webhook", URL: ""}}, quiet())
	if len(n.hooks) != 1 || !n.hooks[0].on[OnFailure] || !n.hooks[0].on[OnBlocked] || n.hooks[0].on[OnSuccess] {
		t.Fatalf("hooks %+v", n.hooks)
	}
	for status, want := range map[string]string{"passed": OnSuccess, "blocked": OnBlocked, "failed": OnFailure, "error": OnFailure} {
		if Class(status) != want {
			t.Errorf("Class(%s) = %s", status, Class(status))
		}
	}
}
