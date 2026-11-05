package mask

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/desnarong/pgsafe/agent/internal/scan"
)

// TableKey is the per-table rule key, e.g. public.sessions: { _table: { strategy: truncate } }.
const TableKey = "_table"

// Strategies (design doc §3.6, plus fake_card / fake_ip / json_mask).
var strategies = map[string]bool{
	"keep": true, "null": true, "static": true, "hash": true,
	"fake_email": true, "fake_phone_th": true, "fake_thai_id": true, "fake_card": true, "fake_ip": true,
	"fake_name_th": true, "fake_name_en": true, "fake_address_th": true,
	"date_shift": true, "number_noise": true, "redact": true, "json_mask": true, "sql": true,
	"truncate": true,
}

// jsonKeyStrategies may be used inside json_mask keys.
var jsonKeyStrategies = map[string]bool{
	"null": true, "hash": true, "redact": true, "fake_email": true, "fake_phone_th": true,
	"fake_thai_id": true, "fake_card": true, "fake_name_th": true, "fake_name_en": true, "fake_address_th": true,
}

// Rule masks one column (or a whole table under TableKey).
type Rule struct {
	Strategy   string            `yaml:"strategy"`
	Reviewed   bool              `yaml:"reviewed"`
	MaxDays    int               `yaml:"max_days,omitempty"` // date_shift
	Value      *string           `yaml:"value,omitempty"`    // static
	Pct        float64           `yaml:"pct,omitempty"`      // number_noise
	Expr       string            `yaml:"expr,omitempty"`     // sql: expression over the column, e.g. "left(email, 2) || '***'"
	Part       string            `yaml:"part,omitempty"`     // fake_name_*: full | first | last
	Keys       map[string]string `yaml:"keys,omitempty"`     // json_mask: top-level key → strategy
	Detector   string            `yaml:"detector,omitempty"` // informational, written by scan
	Confidence string            `yaml:"confidence,omitempty"`
}

// Rules is pgsafe.masking.yaml.
type Rules struct {
	Version int                        `yaml:"version"`
	Tables  map[string]map[string]Rule `yaml:"tables"`
}

// LoadRules reads the rules file; a missing file yields empty rules.
func LoadRules(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Rules{Version: 1, Tables: map[string]map[string]Rule{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read masking rules: %w", err)
	}
	return ParseRules(data)
}

func ParseRules(data []byte) (*Rules, error) {
	r := &Rules{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(r); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse masking rules: %w", err)
	}
	if r.Version == 0 {
		r.Version = 1
	}
	if r.Tables == nil {
		r.Tables = map[string]map[string]Rule{}
	}
	return r, r.Validate()
}

// Validate checks strategies and their parameters.
func (r *Rules) Validate() error {
	var errs []error
	if r.Version != 1 {
		errs = append(errs, fmt.Errorf("masking rules: version must be 1"))
	}
	for table, cols := range r.Tables {
		if !strings.Contains(table, ".") {
			errs = append(errs, fmt.Errorf("%s: table must be schema-qualified (e.g. public.%s)", table, table))
		}
		for col, rule := range cols {
			p := table + "." + col
			if err := rule.validate(col == TableKey); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (r Rule) validate(table bool) error {
	if !strategies[r.Strategy] {
		return fmt.Errorf("unknown strategy %q", r.Strategy)
	}
	if table {
		if r.Strategy != "truncate" && r.Strategy != "keep" {
			return fmt.Errorf("%s supports only truncate or keep", TableKey)
		}
		return nil
	}
	switch r.Strategy {
	case "truncate":
		return fmt.Errorf("truncate applies to a whole table; use %s: { strategy: truncate }", TableKey)
	case "static":
		if r.Value == nil {
			return errors.New("static needs value")
		}
	case "date_shift":
		if r.MaxDays < 0 {
			return errors.New("date_shift max_days must be > 0")
		}
	case "number_noise":
		if r.Pct <= 0 || r.Pct > 100 {
			return errors.New("number_noise needs pct between 0 and 100")
		}
	case "sql":
		if strings.TrimSpace(r.Expr) == "" {
			return errors.New("sql needs expr")
		}
	case "json_mask":
		if len(r.Keys) == 0 {
			return errors.New("json_mask needs keys")
		}
		for k, s := range r.Keys {
			if !jsonKeyStrategies[s] {
				return fmt.Errorf("json_mask key %q: strategy %q not allowed inside JSON", k, s)
			}
		}
	}
	switch r.Part {
	case "", "full", "first", "last":
	default:
		return fmt.Errorf("part must be full, first or last")
	}
	return nil
}

// Unreviewed returns "table.column" keys of rules a human has not reviewed.
// Table-level rules (truncate) are inherently safe and never need review.
func (r *Rules) Unreviewed() []string {
	var out []string
	for table, cols := range r.Tables {
		for col, rule := range cols {
			if col != TableKey && !rule.Reviewed {
				out = append(out, table+"."+col)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Has reports whether a rule exists for table.column.
func (r *Rules) Has(table, column string) bool {
	_, ok := r.Tables[table][column]
	return ok
}

// MergeResult describes what MergeFindings changed.
type MergeResult struct {
	Added   []string `json:"added"`   // new unreviewed rules
	Updated []string `json:"updated"` // unreviewed rules refreshed from the scan
	Kept    []string `json:"kept"`    // reviewed rules left untouched
	Stale   []string `json:"stale"`   // rules for columns that no longer exist
}

// MergeFindings updates the YAML in data (may be empty) with blocking
// findings. Reviewed rules are never modified; comments and ordering are
// preserved. existing lists every "table.column" present in the database, to
// report stale rules.
func MergeFindings(data []byte, findings []scan.Finding, existing map[string]bool, now time.Time) ([]byte, *MergeResult, error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(data)) > 0 {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, nil, fmt.Errorf("parse masking rules: %w", err)
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
		doc.HeadComment = "pgsafe masking rules — set reviewed: true after checking each rule.\nStrategies: see pgsafe.masking.example.yaml (https://github.com/desnarong/pgsafe)"
	}
	root := doc.Content[0]
	if v := mapGet(root, "version"); v == nil {
		mapSet(root, "version", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"}, true)
	}
	tables := mapGet(root, "tables")
	if tables == nil || tables.Kind != yaml.MappingNode {
		tables = &yaml.Node{Kind: yaml.MappingNode}
		mapSet(root, "tables", tables, false)
	}

	res := &MergeResult{Added: []string{}, Updated: []string{}, Kept: []string{}, Stale: []string{}}
	stamp := "added by pgsafe scan " + now.UTC().Format("2006-01-02")
	for _, f := range findings {
		if !scan.Blocking(f.Confidence) {
			continue
		}
		tnode := mapGet(tables, f.Table)
		if tnode == nil || tnode.Kind != yaml.MappingNode {
			tnode = &yaml.Node{Kind: yaml.MappingNode}
			mapSet(tables, f.Table, tnode, false)
		}
		key := f.Table + "." + f.Column
		if cur := mapGet(tnode, f.Column); cur != nil {
			var rule Rule
			if err := cur.Decode(&rule); err == nil && rule.Reviewed {
				res.Kept = append(res.Kept, key)
				continue
			}
			*cur = *ruleNode(f)
			cur.LineComment = stamp
			res.Updated = append(res.Updated, key)
			continue
		}
		n := ruleNode(f)
		n.LineComment = stamp
		mapSet(tnode, f.Column, n, false)
		res.Added = append(res.Added, key)
	}

	if existing != nil {
		for i := 0; i+1 < len(tables.Content); i += 2 {
			t := tables.Content[i].Value
			cols := tables.Content[i+1]
			for j := 0; j+1 < len(cols.Content); j += 2 {
				c := cols.Content[j].Value
				if c != TableKey && !existing[t+"."+c] {
					res.Stale = append(res.Stale, t+"."+c)
				}
			}
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, nil, err
	}
	out := buf.Bytes()
	if _, err := ParseRules(out); err != nil {
		return nil, nil, fmt.Errorf("merged rules are invalid: %w", err)
	}
	return out, res, nil
}

// ruleNode renders a finding as a flow-style mapping:
// { strategy: fake_email, reviewed: false, detector: email, confidence: high }
func ruleNode(f scan.Finding) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
	add := func(k string, v *yaml.Node) {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, v)
	}
	str := func(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: s} }
	add("strategy", str(f.Strategy))
	add("reviewed", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
	if v, ok := f.Params["max_days"]; ok {
		add("max_days", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(v)})
	}
	if v, ok := f.Params["part"]; ok {
		add("part", str(fmt.Sprint(v)))
	}
	if len(f.JSONKeys) > 0 {
		keys := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
		names := make([]string, 0, len(f.JSONKeys))
		for k := range f.JSONKeys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			keys.Content = append(keys.Content, str(k), str(f.JSONKeys[k]))
		}
		add("keys", keys)
	}
	add("detector", str(f.Detector))
	add("confidence", str(f.Confidence))
	return n
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapSet appends key: v (or prepends when first is true).
func mapSet(m *yaml.Node, key string, v *yaml.Node, first bool) {
	k := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	if first {
		m.Content = append([]*yaml.Node{k, v}, m.Content...)
		return
	}
	m.Content = append(m.Content, k, v)
}

// CloudRule is a masking decision reviewed in the control plane.
type CloudRule struct {
	Table    string
	Column   string
	Strategy string
	Params   map[string]any
}

// ApplyCloudRules writes reviewed decisions from the dashboard into the rules
// YAML (the cloud is the source of truth for these columns when
// rules_source is cloud). Other rules and comments are left alone.
func ApplyCloudRules(data []byte, rules []CloudRule) ([]byte, int, error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(data)) > 0 {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, 0, fmt.Errorf("parse masking rules: %w", err)
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if mapGet(root, "version") == nil {
		mapSet(root, "version", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"}, true)
	}
	tables := mapGet(root, "tables")
	if tables == nil || tables.Kind != yaml.MappingNode {
		tables = &yaml.Node{Kind: yaml.MappingNode}
		mapSet(root, "tables", tables, false)
	}
	changed := 0
	for _, cr := range rules {
		want := Rule{Strategy: cr.Strategy, Reviewed: true}
		applyParams(&want, cr.Params)
		if err := want.validate(cr.Column == TableKey); err != nil {
			return nil, 0, fmt.Errorf("%s.%s: %w", cr.Table, cr.Column, err)
		}
		tnode := mapGet(tables, cr.Table)
		if tnode == nil || tnode.Kind != yaml.MappingNode {
			tnode = &yaml.Node{Kind: yaml.MappingNode}
			mapSet(tables, cr.Table, tnode, false)
		}
		if cur := mapGet(tnode, cr.Column); cur != nil {
			var have Rule
			if cur.Decode(&have) == nil && sameDecision(have, want) {
				continue
			}
			*cur = *reviewedNode(want)
		} else {
			mapSet(tnode, cr.Column, reviewedNode(want), false)
		}
		changed++
	}
	if changed == 0 {
		return data, 0, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, 0, err
	}
	if _, err := ParseRules(buf.Bytes()); err != nil {
		return nil, 0, fmt.Errorf("rules from the control plane are invalid: %w", err)
	}
	return buf.Bytes(), changed, nil
}

func applyParams(r *Rule, p map[string]any) {
	num := func(v any) float64 {
		switch x := v.(type) {
		case float64:
			return x
		case int:
			return float64(x)
		}
		return 0
	}
	for k, v := range p {
		switch k {
		case "max_days":
			r.MaxDays = int(num(v))
		case "pct":
			r.Pct = num(v)
		case "value":
			s := fmt.Sprint(v)
			r.Value = &s
		case "expr":
			r.Expr = fmt.Sprint(v)
		case "part":
			r.Part = fmt.Sprint(v)
		case "keys":
			if m, ok := v.(map[string]any); ok {
				r.Keys = map[string]string{}
				for kk, vv := range m {
					r.Keys[kk] = fmt.Sprint(vv)
				}
			}
		}
	}
}

func sameDecision(a, b Rule) bool {
	if a.Strategy != b.Strategy || a.Reviewed != b.Reviewed || a.MaxDays != b.MaxDays || a.Pct != b.Pct || a.Expr != b.Expr || a.Part != b.Part {
		return false
	}
	if (a.Value == nil) != (b.Value == nil) || (a.Value != nil && *a.Value != *b.Value) || len(a.Keys) != len(b.Keys) {
		return false
	}
	for k, v := range a.Keys {
		if b.Keys[k] != v {
			return false
		}
	}
	return true
}

func reviewedNode(r Rule) *yaml.Node {
	var n yaml.Node
	_ = n.Encode(r)
	n.Style = yaml.FlowStyle
	n.LineComment = "reviewed in pgsafe cloud"
	return &n
}
