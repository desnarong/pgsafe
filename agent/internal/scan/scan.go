package scan

import (
	"fmt"
	"sort"
	"strings"
)

// Confidence levels. Only high and medium block staging when unreviewed.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Column is a column to classify, with sampled non-null values rendered as
// text. Samples stay in memory: they are never logged, stored or sent.
type Column struct {
	Table   string // schema-qualified, e.g. public.customers
	Name    string
	Type    string // format_type(), e.g. "character varying(255)", "jsonb", "date"
	Comment string
	Samples []string
}

// Finding is the classification of one column. It carries no data values.
type Finding struct {
	Table      string            `json:"table" yaml:"table"`
	Column     string            `json:"column" yaml:"column"`
	Detector   string            `json:"detector" yaml:"detector"`
	Confidence string            `json:"confidence" yaml:"confidence"`
	Strategy   string            `json:"strategy" yaml:"strategy"`
	Params     map[string]any    `json:"params,omitempty" yaml:"params,omitempty"`
	Reason     string            `json:"reason" yaml:"reason"`
	JSONKeys   map[string]string `json:"json_keys,omitempty" yaml:"json_keys,omitempty"`
}

func (f Finding) Key() string { return f.Table + "." + f.Column }

// Blocking reports whether an unreviewed finding of this confidence blocks staging.
func Blocking(confidence string) bool { return confidence == High || confidence == Medium }

func typeKind(t string) string {
	t = strings.ToLower(t)
	switch {
	case strings.HasSuffix(t, "[]"):
		return "array"
	case t == "json" || t == "jsonb":
		return "json"
	case t == "inet" || t == "cidr":
		return "inet"
	case t == "date" || strings.HasPrefix(t, "timestamp"):
		return "date"
	case strings.HasPrefix(t, "character") || t == "text" || t == "citext" || t == "name" || strings.HasPrefix(t, "varchar") || strings.HasPrefix(t, "char"):
		return "text"
	case t == "bigint" || t == "integer" || t == "smallint" || strings.HasPrefix(t, "numeric"):
		return "number"
	default:
		return "other"
	}
}

// NeedsSamples reports whether Classify uses sample values for this column.
func NeedsSamples(name, typ, comment string) bool {
	switch typeKind(typ) {
	case "text", "json", "inet":
		return true
	case "number":
		_, ok := hintFor(name, comment)
		return ok
	}
	return false
}

// Classify decides whether a column holds PII. ok is false when it does not.
func Classify(c Column) (Finding, bool) {
	kind := typeKind(c.Type)
	hint, hinted := hintFor(c.Name, c.Comment)
	f := Finding{Table: c.Table, Column: c.Name}

	switch kind {
	case "inet":
		f.Detector, f.Confidence, f.Reason = DetIP, High, "inet column"
		f.Strategy = strategyFor(f.Detector, kind, hint.part, c.Samples)
		return f, true
	case "date":
		if hinted && hint.detector == DetBirth {
			f.Detector, f.Confidence, f.Reason = DetBirth, High, "column name"
			f.Strategy, f.Params = "date_shift", map[string]any{"max_days": 180}
			return f, true
		}
		return f, false
	case "json":
		return classifyJSON(c)
	case "array", "other":
		return f, false
	}

	// Value detectors: best match ratio over non-empty samples.
	bestDet, bestRatio := "", 0.0
	if len(c.Samples) > 0 {
		for _, d := range valueDetectors {
			n := 0
			for _, s := range c.Samples {
				if d.fn(s) {
					n++
				}
			}
			if r := float64(n) / float64(len(c.Samples)); r > bestRatio {
				bestDet, bestRatio = d.name, r
			}
		}
	}
	valueConf := ""
	switch {
	case bestRatio >= 0.8:
		valueConf = High
	case bestRatio >= 0.3:
		valueConf = Medium
	case bestRatio >= 0.05:
		valueConf = Low
	}

	// Free text: long values with embedded PII → redact.
	if kind == "text" && avgLen(c.Samples) >= 30 && (valueConf == "" || valueConf == Low) {
		n := 0
		for _, s := range c.Samples {
			if ContainsPII(s) {
				n++
			}
		}
		if r := float64(n) / float64(max(len(c.Samples), 1)); r >= 0.05 {
			f.Detector, f.Strategy = DetFreeText, "redact"
			f.Confidence = Medium
			if r >= 0.3 {
				f.Confidence = High
			}
			f.Reason = "PII patterns inside free text (" + pct(r) + " of sampled rows)"
			return f, true
		}
	}

	switch {
	case valueConf != "" && hinted && compatible(hint.detector, bestDet):
		f.Detector, f.Confidence = hint.detector, bump(valueConf)
		f.Reason = "column name + values (" + pct(bestRatio) + " " + bestDet + ")"
	case valueConf == High || valueConf == Medium:
		f.Detector, f.Confidence = bestDet, valueConf
		f.Reason = "values (" + pct(bestRatio) + " " + bestDet + ")"
	case hinted:
		f.Detector = hint.detector
		f.Confidence = Low
		if hint.strong {
			f.Confidence = Medium
		}
		f.Reason = "column name"
		if c.Comment != "" && !nameMatches(c.Name) {
			f.Reason = "column comment"
		}
	case valueConf == Low:
		f.Detector, f.Confidence = bestDet, Low
		f.Reason = "values (" + pct(bestRatio) + " " + bestDet + ")"
	default:
		return f, false
	}
	part := hint.part
	if !hinted || hint.detector != DetNameTH {
		part = "full"
	}
	f.Strategy = strategyFor(f.Detector, kind, part, c.Samples)
	if f.Detector == DetNameTH || f.Detector == DetNameEN {
		f.Params = map[string]any{"part": part}
		if f.Strategy == "fake_name_en" {
			f.Detector = DetNameEN
		}
	}
	return f, true
}

func nameMatches(name string) bool { _, ok := hintFor(name, ""); return ok }

// compatible: a column-name hint and a value detector agree.
func compatible(hint, value string) bool {
	if hint == value {
		return true
	}
	switch hint {
	case DetTaxID:
		return value == DetThaiID
	case DetNameTH, DetNameEN:
		return value == DetNameTH
	}
	return false
}

func bump(c string) string {
	switch c {
	case Low:
		return Medium
	default:
		return High
	}
}

func pct(r float64) string { return fmt.Sprintf("%.0f%%", r*100) }

// strategyFor suggests a masking strategy compatible with the column type.
func strategyFor(det, kind, part string, samples []string) string {
	switch det {
	case DetEmail:
		return "fake_email"
	case DetPhoneTH:
		return "fake_phone_th"
	case DetThaiID, DetTaxID:
		return "fake_thai_id"
	case DetCard:
		return "fake_card"
	case DetIP:
		return "fake_ip"
	case DetAddrTH:
		return "fake_address_th"
	case DetBirth:
		return "date_shift"
	case DetNameTH, DetNameEN:
		if mostlyLatin(samples) {
			return "fake_name_en"
		}
		return "fake_name_th"
	case DetFreeText:
		return "redact"
	}
	if kind == "number" {
		return "null"
	}
	return "hash"
}

// classifyJSON flags json/jsonb columns whose top-level keys hold PII and
// suggests json_mask with a strategy per key.
func classifyJSON(c Column) (Finding, bool) {
	f := Finding{Table: c.Table, Column: c.Name, Detector: DetJSON}
	objs := jsonObjects(c.Samples)
	if len(objs) == 0 {
		return f, false
	}
	keyVals := map[string][]string{}
	for _, o := range objs {
		for k, v := range o {
			if s, ok := v.(string); ok {
				keyVals[k] = append(keyVals[k], s)
			} else if _, isObj := v.(map[string]any); !isObj {
				keyVals[k] = append(keyVals[k], "")
			}
		}
	}
	keys := map[string]string{}
	best := ""
	for k, vals := range keyVals {
		var nonEmpty []string
		for _, v := range vals {
			if v != "" {
				nonEmpty = append(nonEmpty, v)
			}
		}
		sub, ok := Classify(Column{Table: c.Table, Name: k, Type: "text", Samples: nonEmpty})
		if !ok || !Blocking(sub.Confidence) || sub.Strategy == "redact" && sub.Confidence != High {
			continue
		}
		strategy := sub.Strategy
		if strategy == "date_shift" || strategy == "fake_ip" {
			strategy = "hash"
		}
		keys[k] = strategy
		if best == "" || sub.Confidence == High {
			best = sub.Confidence
		}
	}
	if len(keys) == 0 {
		return f, false
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	f.Confidence, f.Strategy, f.JSONKeys = best, "json_mask", keys
	f.Reason = "JSON keys: " + strings.Join(names, ", ")
	return f, true
}

// SortFindings orders findings by table then column.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Table != fs[j].Table {
			return fs[i].Table < fs[j].Table
		}
		return fs[i].Column < fs[j].Column
	})
}
