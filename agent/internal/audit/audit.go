// Package audit records sensitive actions (real restores) to
// state_dir/audit.jsonl. Entries hold metadata only; URLs are redacted.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

type Entry struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"` // restore
	Actor    string    `json:"actor"`  // OS user
	Host     string    `json:"host"`
	Database string    `json:"database"`
	BackupID string    `json:"backup_id"`
	Target   string    `json:"target"` // redacted URL
	Replace  bool      `json:"replace"`
	KeptAs   string    `json:"kept_as,omitempty"`
	Status   string    `json:"status"`
	Error    string    `json:"error,omitempty"`
}

// Actor returns "user@host" for the current process.
func Actor() (string, string) {
	host, _ := os.Hostname()
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return name, host
}

// Append writes e to dir/audit.jsonl.
func Append(dir string, e Entry) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
