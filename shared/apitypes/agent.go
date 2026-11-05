package apitypes

import "time"

// The agent ↔ control plane protocol (design doc §4.2, "Agent API").
// Everything here is metadata: never row data, credentials or masking salts.

// DatabaseInfo is a database the agent manages (from pgsafe.yaml).
type DatabaseInfo struct {
	Name      string `json:"name"`
	PGVersion string `json:"pg_version,omitempty"`
}

// RegisterRequest is sent by `pgsafe login` and repeated by every heartbeat.
type RegisterRequest struct {
	Hostname  string         `json:"hostname"`
	Version   string         `json:"version"`
	Databases []DatabaseInfo `json:"databases"`
}

type DatabaseRef struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type RegisterResponse struct {
	AgentID   string        `json:"agent_id"`
	AgentName string        `json:"agent_name"`
	OrgID     string        `json:"org_id"`
	OrgName   string        `json:"org_name"`
	Databases []DatabaseRef `json:"databases"`
}

type HeartbeatResponse struct {
	// ConfigVersion changes whenever a policy or reviewed rule changes; the
	// agent then fetches GET /v1/agent/config.
	ConfigVersion   int64     `json:"config_version"`
	CommandsPending int64     `json:"commands_pending"`
	ServerTime      time.Time `json:"server_time"`
}

type Retention struct {
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

type Policy struct {
	BackupCron  string    `json:"backup_cron"`
	VerifyMode  string    `json:"verify_mode"`
	StageMode   string    `json:"stage_mode"`
	Retention   Retention `json:"retention"`
	RulesSource string    `json:"rules_source"` // cloud | git
	Managed     bool      `json:"managed"`      // true: this schedule overrides pgsafe.yaml
}

// Rule is a reviewed masking decision made in the dashboard.
type Rule struct {
	Table    string         `json:"table"` // schema-qualified
	Column   string         `json:"column"`
	Strategy string         `json:"strategy"`
	Params   map[string]any `json:"params,omitempty"`
	Status   string         `json:"status"` // reviewed | ignored (ignored = keep)
}

type DatabaseConfig struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Policy Policy `json:"policy"`
	Rules  []Rule `json:"rules"`
}

type ConfigResponse struct {
	ConfigVersion int64            `json:"config_version"`
	Databases     []DatabaseConfig `json:"databases"`
}

// Command is a "run now" request from the dashboard.
type Command struct {
	ID        string    `json:"id"`
	Database  string    `json:"database"`
	Kind      string    `json:"kind"` // backup | verify | scan | mask | stage
	CreatedAt time.Time `json:"created_at"`
}

type CommandsResponse struct {
	Commands []Command `json:"commands"`
}

type CommandResult struct {
	Status string `json:"status"` // done | failed
	RunID  string `json:"run_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// RunReport is sent when a run starts (status running) and again when it ends.
type RunReport struct {
	ID         string     `json:"id"`
	Database   string     `json:"database"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"` // running | passed | failed | blocked | error | cancelled
	Trigger    string     `json:"trigger"`
	CommandID  string     `json:"command_id,omitempty"`
	BackupID   string     `json:"backup_id,omitempty"`
	Summary    string     `json:"summary,omitempty"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	DurationMS int64      `json:"duration_ms,omitempty"`
	Steps      []Step     `json:"steps,omitempty"`
}

type Verified struct {
	Status            string    `json:"status"`
	RunID             string    `json:"run_id"`
	At                time.Time `json:"at"`
	RestoreDurationMS int64     `json:"restore_duration_ms"`
}

// BackupReport describes a backup or masked dump in the customer's bucket.
type BackupReport struct {
	Database   string    `json:"database"`
	ID         string    `json:"id"`
	Kind       string    `json:"kind"` // backup | masked
	SizeBytes  int64     `json:"size_bytes"`
	SHA256     string    `json:"sha256"`
	SchemaHash string    `json:"schema_hash"`
	TableCount int       `json:"table_count"`
	PGVersion  string    `json:"pg_version"`
	CreatedAt  time.Time `json:"created_at"`
	Verified   *Verified `json:"verified,omitempty"`
}

// Finding is a PII classification of one column — no values.
type Finding struct {
	Table      string         `json:"table"`
	Column     string         `json:"column"`
	Detector   string         `json:"detector"`
	Confidence string         `json:"confidence"`
	Strategy   string         `json:"strategy"`
	Params     map[string]any `json:"params,omitempty"`
}

type FindingsReport struct {
	Database string    `json:"database"`
	Source   string    `json:"source"` // scan | drift
	Findings []Finding `json:"findings"`
}

type FindingsResponse struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
}
