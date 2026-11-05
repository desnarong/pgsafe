package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/robfig/cron/v3"
	"go.yaml.in/yaml/v3"
)

// DefaultFile is the config file name used when --config is not given.
const DefaultFile = "pgsafe.yaml"

type Config struct {
	Version    int        `yaml:"version"`
	StateDir   string     `yaml:"state_dir"` // local run history; relative to the config file
	PGClient   string     `yaml:"pg_client"` // auto | local | docker
	Databases  []Database `yaml:"databases"`
	Storage    Storage    `yaml:"storage"`
	Encryption Encryption `yaml:"encryption"`
	Retention  Retention  `yaml:"retention"`
	Schedule   Schedule   `yaml:"schedule"`
	Verify     Verify     `yaml:"verify"`
	Masking    Masking    `yaml:"masking"`
	Staging    Staging    `yaml:"staging"`
	Notify     []Notify   `yaml:"notify"`
	Cloud      Cloud      `yaml:"cloud"`

	// Path is the absolute path of the loaded file; relative paths resolve against its dir.
	Path string `yaml:"-"`
	// missing maps a YAML path (e.g. "databases[0].url") to the env var it
	// referenced that was not set. Only fields a command actually needs are an error.
	missing map[string]string
}

type Database struct {
	Name             string   `yaml:"name"`
	URL              string   `yaml:"url"`
	ExcludeTables    []string `yaml:"exclude_tables"`
	ExcludeTableData []string `yaml:"exclude_table_data"`
}

type Storage struct {
	Type     string `yaml:"type"`
	Bucket   string `yaml:"bucket"`
	Prefix   string `yaml:"prefix"`
	Region   string `yaml:"region"`
	Endpoint string `yaml:"endpoint"`
}

type Encryption struct {
	Type           string `yaml:"type"` // age | none
	RecipientsFile string `yaml:"recipients_file"`
	IdentityFile   string `yaml:"identity_file"` // needed only to verify/restore
}

type Retention struct {
	Daily   int `yaml:"daily"`
	Weekly  int `yaml:"weekly"`
	Monthly int `yaml:"monthly"`
}

type Schedule struct {
	Backup string `yaml:"backup"`
	Verify string `yaml:"verify"` // after_backup | cron | off
	Stage  string `yaml:"stage"`  // after_verify | cron | off
}

type Verify struct {
	Runtime         string   `yaml:"runtime"` // docker | server
	ServerURL       string   `yaml:"server_url"`
	Jobs            int      `yaml:"jobs"`              // pg_restore --jobs; 0 = auto
	DockerImage     string   `yaml:"docker_image"`      // "{major}" is replaced, default postgres:{major}
	TmpfsBelowBytes int64    `yaml:"tmpfs_below_bytes"` // docker runtime: use tmpfs for small dumps
	RowCount        RowCount `yaml:"row_count"`
	Checks          []Check  `yaml:"checks"`
}

type RowCount struct {
	ExactBelowRows       int64   `yaml:"exact_below_rows"`
	EstimateTolerancePct float64 `yaml:"estimate_tolerance_pct"`
}

type Check struct {
	Type  string `yaml:"type"` // sql
	Name  string `yaml:"name"`
	Query string `yaml:"query"`
}

type Masking struct {
	RulesFile       string `yaml:"rules_file"`
	Salt            string `yaml:"salt"`
	OnUnreviewedPII string `yaml:"on_unreviewed_pii"` // block | mask_default | warn
	ScanOn          string `yaml:"scan_on"`           // scratch | source
	LargeTableRows  int64  `yaml:"large_table_rows"`  // above this, mask with CTAS instead of UPDATE
	PostCheckSample int    `yaml:"post_check_sample"` // rows per column re-checked after masking
	Jobs            int    `yaml:"jobs"`              // tables masked in parallel; 0 = auto
}

// MinSaltLength guards deterministic masking against brute-forcing the salt.
const MinSaltLength = 16

type Staging struct {
	// Encryption of masked dumps. Use a key for the dev team, never the
	// production backup key: whoever can pull would otherwise decrypt backups.
	Encryption Encryption      `yaml:"encryption"`
	Targets    []StagingTarget `yaml:"targets"`
}

type StagingTarget struct {
	Type           string   `yaml:"type"` // database | s3
	URL            string   `yaml:"url"`
	Mode           string   `yaml:"mode"` // replace
	Bucket         string   `yaml:"bucket"`
	Prefix         string   `yaml:"prefix"`
	PreserveTables []string `yaml:"preserve_tables"`
}

// MaskedPrefix is where mask publishes masked dumps (relative to storage.prefix).
const MaskedPrefix = "masked/"

type Notify struct {
	Type string   `yaml:"type"`
	URL  string   `yaml:"url"`
	On   []string `yaml:"on"`
}

type Cloud struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

func defaults() Config {
	return Config{
		StateDir:   ".pgsafe",
		PGClient:   "auto",
		Storage:    Storage{Type: "s3"},
		Encryption: Encryption{Type: "age"},
		Retention:  Retention{Daily: 7, Weekly: 4, Monthly: 6},
		Schedule:   Schedule{Verify: "after_backup", Stage: "off"},
		Verify: Verify{
			Runtime:         "docker",
			DockerImage:     "postgres:{major}",
			TmpfsBelowBytes: 512 << 20,
			RowCount:        RowCount{ExactBelowRows: 5_000_000, EstimateTolerancePct: 2},
		},
		Masking: Masking{
			RulesFile: "./pgsafe.masking.yaml", OnUnreviewedPII: "block", ScanOn: "scratch",
			LargeTableRows: 1_000_000, PostCheckSample: 1000,
		},
		Staging: Staging{Encryption: Encryption{Type: "none"}},
	}
}

// Load reads, env-expands and validates the config at path.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data, os.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = abs
	return cfg, nil
}

// Parse decodes and validates config bytes. lookup resolves ${VAR} references.
func Parse(data []byte, lookup func(string) (string, bool)) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if root.Kind == 0 {
		return nil, errors.New("config is empty")
	}

	missing := map[string]string{}
	if err := checkLiteralCredentials(&root); err != nil {
		return nil, err
	}
	expandNode(&root, "", lookup, missing)

	cfg := defaults()
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(&buf)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	cfg.missing = missing
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandNode replaces ${VAR} inside scalar values (never keys or structure),
// recording unset variables against their YAML path.
func expandNode(n *yaml.Node, path string, lookup func(string) (string, bool), missing map[string]string) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			expandNode(c, path, lookup, missing)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			p := key
			if path != "" {
				p = path + "." + key
			}
			expandNode(n.Content[i+1], p, lookup, missing)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			expandNode(c, fmt.Sprintf("%s[%d]", path, i), lookup, missing)
		}
	case yaml.ScalarNode:
		if !strings.Contains(n.Value, "${") {
			return
		}
		n.Value = envRef.ReplaceAllStringFunc(n.Value, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := lookup(name)
			if !ok || v == "" {
				missing[path] = name
				return ""
			}
			return v
		})
		n.Tag = "!!str"
		n.Style = yaml.DoubleQuotedStyle
	}
}

// credentialKeys are fields that may contain a password; they must come from env.
var credentialKeys = map[string]bool{"url": true, "server_url": true}

func checkLiteralCredentials(root *yaml.Node) error {
	var walk func(n *yaml.Node, path string) error
	walk = func(n *yaml.Node, path string) error {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				if err := walk(c, path); err != nil {
					return err
				}
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				if err := walk(c, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i].Value, n.Content[i+1]
				p := k
				if path != "" {
					p = path + "." + k
				}
				if credentialKeys[k] && v.Kind == yaml.ScalarNode && !strings.Contains(v.Value, "${") && hasPassword(v.Value) {
					return fmt.Errorf("%s: credentials must not be written in the config file; use an env var like ${PROD_DATABASE_URL}", p)
				}
				if err := walk(v, p); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(root, "")
}

func hasPassword(raw string) bool {
	if strings.Contains(strings.ToLower(raw), "password=") {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return false
	}
	_, ok := u.User.Password()
	return ok
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func (c *Config) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Version != 1 {
		add("version: must be 1 (got %d)", c.Version)
	}
	switch c.PGClient {
	case "auto", "local", "docker":
	default:
		add("pg_client: must be auto, local or docker")
	}
	if len(c.Databases) == 0 {
		add("databases: at least one database is required")
	}
	seen := map[string]bool{}
	for i, d := range c.Databases {
		if !nameRe.MatchString(d.Name) {
			add("databases[%d].name: %q must be lowercase letters, digits, '-' or '_'", i, d.Name)
		}
		if seen[d.Name] {
			add("databases[%d].name: duplicate %q", i, d.Name)
		}
		seen[d.Name] = true
	}
	if c.Storage.Type != "s3" {
		add("storage.type: only s3 is supported")
	}
	if c.Storage.Bucket == "" {
		add("storage.bucket: required")
	}
	switch c.Encryption.Type {
	case "age":
		if c.Encryption.RecipientsFile == "" {
			add("encryption.recipients_file: required when encryption.type is age")
		}
	case "none":
	default:
		add("encryption.type: must be age or none")
	}
	if c.Retention.Daily < 0 || c.Retention.Weekly < 0 || c.Retention.Monthly < 0 {
		add("retention: values must be >= 0")
	}
	if c.Schedule.Backup != "" {
		if _, err := cron.ParseStandard(c.Schedule.Backup); err != nil {
			add("schedule.backup: %v", err)
		}
	}
	for field, v := range map[string]string{"schedule.verify": c.Schedule.Verify, "schedule.stage": c.Schedule.Stage} {
		if v == "" || v == "off" || v == "after_backup" || v == "after_verify" {
			continue
		}
		if _, err := cron.ParseStandard(v); err != nil {
			add("%s: must be after_backup, after_verify, off or a cron expression: %v", field, err)
		}
	}
	switch c.Verify.Runtime {
	case "docker", "server":
	default:
		add("verify.runtime: must be docker or server")
	}
	if c.Verify.Jobs < 0 {
		add("verify.jobs: must be >= 0")
	}
	if c.Verify.RowCount.EstimateTolerancePct < 0 || c.Verify.RowCount.EstimateTolerancePct > 100 {
		add("verify.row_count.estimate_tolerance_pct: must be between 0 and 100")
	}
	for i, ch := range c.Verify.Checks {
		if ch.Type != "sql" {
			add("verify.checks[%d].type: only sql is supported", i)
		}
		if ch.Name == "" || ch.Query == "" {
			add("verify.checks[%d]: name and query are required", i)
		}
	}
	switch c.Masking.OnUnreviewedPII {
	case "block", "mask_default", "warn":
	default:
		add("masking.on_unreviewed_pii: must be block, mask_default or warn")
	}
	switch c.Masking.ScanOn {
	case "scratch", "source":
	default:
		add("masking.scan_on: must be scratch or source")
	}
	if c.Masking.LargeTableRows < 0 || c.Masking.PostCheckSample < 0 || c.Masking.Jobs < 0 {
		add("masking: large_table_rows, post_check_sample and jobs must be >= 0")
	}
	for i, n := range c.Notify {
		if n.Type != "webhook" {
			add("notify[%d].type: only webhook is supported by the agent (Slack, LINE and email come with the hosted control plane)", i)
		}
		for _, on := range n.On {
			switch on {
			case "failure", "blocked", "success":
			default:
				add("notify[%d].on: %q must be failure, blocked or success", i, on)
			}
		}
	}
	switch c.Staging.Encryption.Type {
	case "none":
	case "age":
		if c.Staging.Encryption.RecipientsFile == "" {
			add("staging.encryption.recipients_file: required when staging.encryption.type is age")
		}
		if c.Staging.Encryption.RecipientsFile != "" && c.Staging.Encryption.RecipientsFile == c.Encryption.RecipientsFile {
			add("staging.encryption.recipients_file: use a separate key for masked dumps, not the backup key")
		}
	default:
		add("staging.encryption.type: must be age or none")
	}
	for i, t := range c.Staging.Targets {
		switch t.Type {
		case "database":
			if t.Mode != "" && t.Mode != "replace" {
				add("staging.targets[%d].mode: only replace is supported", i)
			}
		case "s3":
		default:
			add("staging.targets[%d].type: must be database or s3", i)
		}
	}
	return errors.Join(errs...)
}

// RequireSalt checks masking.salt for commands that mask.
func (c *Config) RequireSalt() error {
	if err := c.Require(map[string]string{"masking.salt": c.Masking.Salt}); err != nil {
		return err
	}
	if len(c.Masking.Salt) < MinSaltLength {
		return fmt.Errorf("masking.salt: must be at least %d characters (generate one with: openssl rand -hex 32)", MinSaltLength)
	}
	return nil
}

// StagingURLField returns the YAML path for staging.targets[i].url (for Require).
func (c *Config) StagingURLField(i int) string { return fmt.Sprintf("staging.targets[%d].url", i) }

// Database returns the database config by name.
func (c *Config) Database(name string) (*Database, error) {
	for i := range c.Databases {
		if c.Databases[i].Name == name {
			return &c.Databases[i], nil
		}
	}
	return nil, fmt.Errorf("database %q is not in the config", name)
}

// Select returns the named database, or all of them when name is empty.
func (c *Config) Select(name string) ([]Database, error) {
	if name == "" {
		return c.Databases, nil
	}
	d, err := c.Database(name)
	if err != nil {
		return nil, err
	}
	return []Database{*d}, nil
}

// Require returns an error naming the env var behind each listed field that
// was referenced but unset, or that is simply empty.
func (c *Config) Require(fields map[string]string) error {
	var errs []error
	for path, value := range fields {
		if v, ok := c.missing[path]; ok {
			errs = append(errs, fmt.Errorf("%s: env var %s is not set", path, v))
		} else if value == "" {
			errs = append(errs, fmt.Errorf("%s: required", path))
		}
	}
	return errors.Join(errs...)
}

// DatabaseURLField is the YAML path of databases[i].url for Require.
func (c *Config) DatabaseURLField(name string) string {
	for i := range c.Databases {
		if c.Databases[i].Name == name {
			return fmt.Sprintf("databases[%d].url", i)
		}
	}
	return "databases[?].url"
}

// Resolve makes p absolute relative to the config file's directory.
func (c *Config) Resolve(p string) string {
	if p == "" || filepath.IsAbs(p) || c.Path == "" {
		return p
	}
	return filepath.Join(filepath.Dir(c.Path), p)
}

// NormPrefix returns storage.prefix normalized to end with "/" (or empty).
func (s Storage) NormPrefix() string {
	p := strings.TrimLeft(s.Prefix, "/")
	if p != "" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}
