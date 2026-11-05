package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := newRootCmd(&out, &errOut)
	cmd.SetArgs([]string{"version", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var info versionInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if info.Version == "" || info.GoVersion == "" || info.Platform == "" {
		t.Fatalf("missing fields: %+v", info)
	}
}

func TestVersionText(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd(&out, &out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.HasPrefix(out.String(), "pgsafe ") {
		t.Fatalf("unexpected output %q", out.String())
	}
}

// install.sh and the release smoke test call `pgsafe --version`.
func TestVersionFlag(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd(&out, &out)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	want := "pgsafe " + version + " (" + commit + ")\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}
