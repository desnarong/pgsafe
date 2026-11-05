// Package runlog keeps the local history of runs as JSON lines in state_dir.
// It stores metadata only. (With the cloud, runs are reported to the control
// plane instead — Phase 4.)
package runlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const fileName = "runs.jsonl"

type Run struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"` // backup | verify
	Database   string    `json:"database"`
	BackupID   string    `json:"backup_id,omitempty"`
	Status     string    `json:"status"` // passed | failed | error
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
	Summary    string    `json:"summary,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Append adds a run to dir/runs.jsonl, creating dir if needed.
func Append(dir string, r Run) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, fileName), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open run log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("write run log: %w", err)
	}
	return f.Close()
}

// Read returns up to limit runs (0 = all), newest first. Corrupt lines are skipped.
func Read(dir string, limit int) ([]Run, error) {
	f, err := os.Open(filepath.Join(dir, fileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var runs []Run
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r Run
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			runs = append(runs, r)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(runs)-1; i < j; i, j = i+1, j-1 {
		runs[i], runs[j] = runs[j], runs[i]
	}
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	return runs, nil
}
