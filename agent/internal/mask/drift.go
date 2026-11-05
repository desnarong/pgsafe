package mask

import (
	"fmt"
	"sort"
	"strings"

	"github.com/desnarong/pgsafe/agent/internal/scan"
)

// Policies for masking.on_unreviewed_pii.
const (
	PolicyBlock       = "block"
	PolicyMaskDefault = "mask_default"
	PolicyWarn        = "warn"
)

// Blocked is a column that stops masking until a human reviews it.
type Blocked struct {
	Table      string `json:"table"`
	Column     string `json:"column"`
	Reason     string `json:"reason"` // "unreviewed rule" | "new column without a rule"
	Detector   string `json:"detector,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Strategy   string `json:"suggested_strategy,omitempty"`
}

func (b Blocked) Key() string { return b.Table + "." + b.Column }

// Decision is the outcome of the drift check.
type Decision struct {
	Blocked     []Blocked                  `json:"blocked"`
	AutoApplied []string                   `json:"auto_applied"` // mask_default: rules applied without review
	Warnings    []string                   `json:"warnings"`
	Stale       []string                   `json:"stale_rules"` // rules for columns that do not exist
	Effective   map[string]map[string]Rule `json:"-"`           // table → column → rule to apply
}

// Decide applies the fail-closed policy. existing holds every
// "schema.table.column" in the database; findings are scan results for
// columns that have no rule.
func Decide(rules *Rules, existing map[string]bool, findings []scan.Finding, policy string) *Decision {
	d := &Decision{Blocked: []Blocked{}, AutoApplied: []string{}, Warnings: []string{}, Stale: []string{},
		Effective: map[string]map[string]Rule{}}
	tableExists := map[string]bool{}
	for k := range existing {
		tableExists[k[:strings.LastIndexByte(k, '.')]] = true
	}
	set := func(table, col string, r Rule) {
		if d.Effective[table] == nil {
			d.Effective[table] = map[string]Rule{}
		}
		d.Effective[table][col] = r
	}

	for table, cols := range rules.Tables {
		for col, r := range cols {
			key := table + "." + col
			if col == TableKey {
				if tableExists[table] {
					set(table, col, r)
				} else {
					d.Stale = append(d.Stale, table)
				}
				continue
			}
			if !existing[key] {
				d.Stale = append(d.Stale, key)
				continue
			}
			if !r.Reviewed {
				switch policy {
				case PolicyBlock:
					d.Blocked = append(d.Blocked, Blocked{Table: table, Column: col, Reason: "unreviewed rule",
						Detector: r.Detector, Confidence: r.Confidence, Strategy: r.Strategy})
				case PolicyMaskDefault:
					d.AutoApplied = append(d.AutoApplied, key)
				case PolicyWarn:
					d.Warnings = append(d.Warnings, key+": rule not reviewed (applied as written)")
				}
			}
			set(table, col, r)
		}
	}

	for _, f := range findings {
		if !scan.Blocking(f.Confidence) || rules.Has(f.Table, f.Column) {
			continue
		}
		if _, truncated := rules.Tables[f.Table][TableKey]; truncated && rules.Tables[f.Table][TableKey].Strategy == "truncate" {
			continue // the whole table is emptied anyway
		}
		switch policy {
		case PolicyBlock:
			d.Blocked = append(d.Blocked, Blocked{Table: f.Table, Column: f.Column, Reason: "new column without a rule",
				Detector: f.Detector, Confidence: f.Confidence, Strategy: f.Strategy})
		case PolicyMaskDefault:
			set(f.Table, f.Column, ruleFromFinding(f))
			d.AutoApplied = append(d.AutoApplied, f.Key()+" ("+f.Strategy+")")
		case PolicyWarn:
			d.Warnings = append(d.Warnings, fmt.Sprintf("%s looks like %s (%s) but has no rule: NOT masked", f.Key(), f.Detector, f.Confidence))
		}
	}
	sort.Slice(d.Blocked, func(i, j int) bool { return d.Blocked[i].Key() < d.Blocked[j].Key() })
	sort.Strings(d.AutoApplied)
	sort.Strings(d.Warnings)
	sort.Strings(d.Stale)
	return d
}

func ruleFromFinding(f scan.Finding) Rule {
	r := Rule{Strategy: f.Strategy, Detector: f.Detector, Confidence: f.Confidence, Keys: f.JSONKeys}
	if v, ok := f.Params["max_days"].(int); ok {
		r.MaxDays = v
	}
	if v, ok := f.Params["part"].(string); ok {
		r.Part = v
	}
	return r
}
