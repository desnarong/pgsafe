// Command pgsafe is the open-source pgsafe agent: backup, verify, scan, mask,
// stage and restore PostgreSQL databases. See https://github.com/desnarong/pgsafe.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/redact"
)

func main() {
	// Ctrl-C / SIGTERM cancel the context; cleanup (scratch containers,
	// databases) runs on a detached context and still completes.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := newRootCmd(os.Stdout, os.Stderr)
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return
	}
	code := exitcode.From(err)
	if !errors.Is(err, exitcode.ErrReported) {
		msg := redact.String(err.Error())
		if f := cmd.PersistentFlags().Lookup("json"); f != nil && f.Value.String() == "true" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"error": msg, "exit_code": code})
		}
		fmt.Fprintln(os.Stderr, "error:", msg)
	}
	os.Exit(code)
}
