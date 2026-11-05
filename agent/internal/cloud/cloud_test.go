package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOutboxOrderRetryAndDrop(t *testing.T) {
	var mu sync.Mutex
	var got []string
	down := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agt_x_secretsecretsecretsecret" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if down {
			w.WriteHeader(503)
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["n"] == "bad" {
			w.WriteHeader(400)
			return
		}
		got = append(got, body["n"])
	}))
	defer srv.Close()
	dir := t.TempDir()
	c := New(&Credentials{URL: srv.URL, Token: "agt_x_secretsecretsecretsecret"}, "test")
	ob := NewOutbox(dir)
	ctx := context.Background()
	for _, n := range []string{"1", "bad", "2"} {
		if err := ob.Enqueue(ctx, "POST", "/v1/agent/runs", map[string]string{"n": n}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, pending, err := ob.Flush(ctx, c); err == nil || pending != 3 {
		t.Fatalf("server down: pending=%d err=%v", pending, err)
	}
	mu.Lock()
	down = false
	mu.Unlock()
	sent, dropped, pending, err := ob.Flush(ctx, c)
	if err != nil || sent != 2 || dropped != 1 || pending != 0 {
		t.Fatalf("flush: sent=%d dropped=%d pending=%d err=%v", sent, dropped, pending, err)
	}
	if strings.Join(got, ",") != "1,2" {
		t.Fatalf("order: %v", got)
	}
	if ob.Len() != 0 {
		t.Fatal("outbox not empty")
	}
}

func TestSafeText(t *testing.T) {
	in := `restore: ERROR: invalid input syntax for type integer: "somchai@gmail.com" | duplicate key: Key (email)=(a@b.co) already exists | postgres://app:hunter22@db/x`
	out := SafeText(in)
	for _, leak := range []string{"somchai@gmail.com", "a@b.co", "hunter22"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "Key (email)=(…)") || !strings.Contains(out, "invalid input syntax for type integer") {
		t.Errorf("message context lost: %s", out)
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	if c, err := LoadCredentials(dir); c != nil || err != nil {
		t.Fatalf("empty: %v %v", c, err)
	}
	if err := SaveCredentials(dir, &Credentials{URL: "https://x", Token: "agt_a_b"}); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCredentials(dir)
	if err != nil || c.Token != "agt_a_b" {
		t.Fatalf("load: %+v %v", c, err)
	}
	t.Setenv("PGSAFE_CLOUD_TOKEN", "agt_env_tok")
	t.Setenv("PGSAFE_CLOUD_URL", "https://env/")
	c, _ = LoadCredentials(dir)
	if c.Token != "agt_env_tok" || c.URL != "https://env" {
		t.Fatalf("env override: %+v", c)
	}
	os.Unsetenv("PGSAFE_CLOUD_TOKEN")
	if err := RemoveCredentials(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, credFile)); !os.IsNotExist(err) {
		t.Fatal("not removed")
	}
	_ = io.Discard
}
