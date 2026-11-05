package dump

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

func TestPattern(t *testing.T) {
	tests := []struct {
		pattern, schema, name string
		want                  bool
	}{
		{"sessions", "public", "sessions", true},
		{"sessions", "app", "sessions", true},
		{"sessions", "public", "sessions_old", false},
		{"cache_*", "public", "cache_pages", true},
		{"cache_*", "public", "mycache_pages", false},
		{"public.cache_?", "public", "cache_1", true},
		{"public.cache_?", "app", "cache_1", false},
		{"*.audit", "x", "audit", true},
		{"a.b", "a", "b", true},
		{"orders", "public", "Orders", false},
		{"t_(x)", "public", "t_(x)", true}, // regex metacharacters are literal
	}
	for _, tt := range tests {
		p, err := CompilePattern(tt.pattern)
		if err != nil {
			t.Fatalf("%s: %v", tt.pattern, err)
		}
		if got := p.Match(tt.schema, tt.name); got != tt.want {
			t.Errorf("%q.Match(%s.%s) = %v, want %v", tt.pattern, tt.schema, tt.name, got, tt.want)
		}
	}
	for _, bad := range []string{"", "a.b.c", "a."} {
		if _, err := CompilePattern(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestTableArgQuotes(t *testing.T) {
	got := TableArg(pg.Table{Schema: "public", Name: `we"ird*`})
	if got != `"public"."we""ird*"` {
		t.Fatalf("TableArg = %s", got)
	}
}

func TestCommandNeverPutsPasswordInArgv(t *testing.T) {
	ci, _ := pg.ParseURL("postgres://app:hunter22@localhost:5414/shop")
	for _, c := range []*Client{
		{Mode: ModeLocal, Major: 16, BinDir: "/usr/lib/postgresql/16/bin"},
		{Mode: ModeDocker, Major: 16, Image: "postgres:16"},
	} {
		for _, cmd := range [][]string{
			c.DumpCommand(context.Background(), ci, []string{"--snapshot=x"}).Args,
			c.RestoreCommand(context.Background(), ci, "/tmp/w/dump.pgc", 4).Args,
		} {
			if strings.Contains(strings.Join(cmd, " "), "hunter22") {
				t.Fatalf("%s: password in argv: %v", c.Mode, cmd)
			}
		}
		env := c.DumpCommand(context.Background(), ci, nil).Env
		if !slices.Contains(env, "PGPASSWORD=hunter22") {
			t.Fatalf("%s: PGPASSWORD not in child env", c.Mode)
		}
	}
}

func TestDockerCommandRewritesLoopback(t *testing.T) {
	ci, _ := pg.ParseURL("postgres://app:pw@localhost:5414/shop")
	c := &Client{Mode: ModeDocker, Major: 16, Image: "postgres:16"}
	args := strings.Join(c.DumpCommand(context.Background(), ci, nil).Args, " ")
	if !strings.Contains(args, "--dbname=postgres://app@host.docker.internal:5414/shop") {
		t.Fatalf("loopback not rewritten: %s", args)
	}
	if !strings.Contains(args, "--add-host=host.docker.internal:host-gateway") {
		t.Fatalf("missing add-host: %s", args)
	}
}

func TestRestoreErrors(t *testing.T) {
	stderr := "pg_restore: warning: something harmless\npg_restore: error: could not execute query: ERROR: x\npg_restore: warning: errors ignored on restore: 1\n"
	got := RestoreErrors(stderr)
	if len(got) != 2 {
		t.Fatalf("RestoreErrors = %v", got)
	}
}

func TestVerMajor(t *testing.T) {
	if verMajor("16.4") != 16 || verMajor("18") != 18 {
		t.Fatal("verMajor")
	}
	m := verRe.FindStringSubmatch("pg_dump (PostgreSQL) 14.13 (Debian 14.13-1.pgdg120+1)")
	if m == nil || m[1] != "14.13" {
		t.Fatalf("verRe: %v", m)
	}
}

func TestTailBuffer(t *testing.T) {
	tb := &TailBuffer{Max: 5}
	tb.Write([]byte("hello world"))
	if tb.String() != "world" {
		t.Fatalf("got %q", tb.String())
	}
}
