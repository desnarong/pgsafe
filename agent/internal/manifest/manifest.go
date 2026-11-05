package manifest

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	FileName       = "manifest.json"
	VerifyFileName = "verify.json"
	FormatCustom   = "custom"
)

// Manifest describes one backup (design doc §3.3). It holds metadata only —
// never row data or credentials.
type Manifest struct {
	BackupID         string    `json:"backup_id"`
	Database         string    `json:"database"`
	CreatedAt        time.Time `json:"created_at"`
	FinishedAt       time.Time `json:"finished_at"`
	DurationMS       int64     `json:"duration_ms"`
	PGServerVersion  string    `json:"pg_server_version"`
	PGServerMajor    int       `json:"pg_server_major"`
	PGDumpVersion    string    `json:"pg_dump_version"`
	Format           string    `json:"format"`
	Encryption       string    `json:"encryption"` // age | none
	Object           string    `json:"object"`     // dump object name inside the backup dir
	SizeBytes        int64     `json:"size_bytes"` // of the stored object
	SHA256           string    `json:"sha256"`     // of the stored object (after encryption)
	SchemaHash       string    `json:"schema_hash"`
	Tables           []Table   `json:"tables"`
	ExcludeTables    []string  `json:"exclude_tables,omitempty"`
	ExcludeTableData []string  `json:"exclude_table_data,omitempty"`
	AgentVersion     string    `json:"agent_version"`

	// Masked dumps only.
	Kind           string `json:"kind,omitempty"` // "" (backup) | "masked"
	SourceBackupID string `json:"source_backup_id,omitempty"`
	RulesSHA256    string `json:"rules_sha256,omitempty"` // of pgsafe.masking.yaml used
}

// KindMasked marks a masked dump manifest.
const KindMasked = "masked"

type Table struct {
	Schema       string `json:"schema"`
	Name         string `json:"name"`
	Rows         int64  `json:"rows"`
	RowsExact    bool   `json:"rows_exact"`
	DataExcluded bool   `json:"data_excluded,omitempty"`
}

func (t Table) Qualified() string { return t.Schema + "." + t.Name }

func (m *Manifest) Marshal() ([]byte, error) { return json.MarshalIndent(m, "", "  ") }

func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.BackupID == "" || m.Object == "" || m.SHA256 == "" {
		return nil, fmt.Errorf("parse manifest: missing backup_id, object or sha256")
	}
	return &m, nil
}

// Status values for verify reports and checks.
const (
	StatusPassed = "passed"
	StatusFailed = "failed"
	StatusError  = "error"   // verification could not run (infra problem)
	StatusSkip   = "skipped" // check not applicable
)

// VerifyReport is written next to the backup as verify.json.
type VerifyReport struct {
	BackupID          string        `json:"backup_id"`
	Database          string        `json:"database"`
	RunID             string        `json:"run_id"`
	Status            string        `json:"status"`
	StartedAt         time.Time     `json:"started_at"`
	FinishedAt        time.Time     `json:"finished_at"`
	DurationMS        int64         `json:"duration_ms"`
	RestoreDurationMS int64         `json:"restore_duration_ms"` // the measured RTO
	Runtime           string        `json:"runtime"`             // docker | server
	TablesTotal       int           `json:"tables_total"`
	TablesOK          int           `json:"tables_ok"`
	Checks            []CheckResult `json:"checks"`
	Error             string        `json:"error,omitempty"`
	AgentVersion      string        `json:"agent_version"`

	// Manifest is the verified backup's manifest (in memory only, for reporting).
	Manifest *Manifest `json:"-"`
}

type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (r *VerifyReport) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

func ParseVerify(data []byte) (*VerifyReport, error) {
	var r VerifyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse verify report: %w", err)
	}
	return &r, nil
}
