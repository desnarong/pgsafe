package mask

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

// Col is a column of a table being masked.
type Col struct {
	Name      string
	Type      string // format_type()
	NotNull   bool
	Generated bool
}

func (c Col) ident() string { return pgx.Identifier{c.Name}.Sanitize() }

// Paths a table can be masked with.
const (
	PathUpdate   = "update"   // UPDATE … SET col = expr
	PathCTAS     = "ctas"     // CREATE UNLOGGED TABLE AS SELECT, TRUNCATE, INSERT back
	PathTruncate = "truncate" // _table: truncate
)

// TablePlan is how one table gets masked.
type TablePlan struct {
	Table  pg.Table
	Cols   []Col
	PK     []string        // primary key columns, if any
	Rules  map[string]Rule // column → rule (only columns that change)
	Path   string
	Rows   int64
	exprs  map[string]string
	rowKey string // SQL expression identifying a row (PK) or "" if none
}

func isArray(t string) bool { return strings.HasSuffix(t, "[]") }
func isJSONB(t string) bool { return t == "jsonb" }
func isJSON(t string) bool  { return t == "json" }
func isDateish(t string) bool {
	return t == "date" || strings.HasPrefix(t, "timestamp")
}

// rowKeyExpr renders the primary key as text ("1" or "1|abc"); "" without a PK.
func rowKeyExpr(pk []string) string {
	if len(pk) == 0 {
		return ""
	}
	parts := make([]string, len(pk))
	for i, c := range pk {
		parts[i] = pgx.Identifier{c}.Sanitize() + "::text"
	}
	return strings.Join(parts, " || '|' || ")
}

// Expr returns the SQL expression producing the masked value of c.
// rowKey is used by row-keyed strategies (date_shift, number_noise).
func Expr(c Col, r Rule, rowKey string) (string, error) {
	col := c.ident()
	cast := "::" + c.Type
	text := col + "::text"
	if isArray(c.Type) {
		switch r.Strategy {
		case "keep", "null", "static", "sql":
		default:
			return "", fmt.Errorf("strategy %s does not support array columns (%s); use null, static or sql", r.Strategy, c.Type)
		}
	}
	key := rowKey
	if key == "" {
		key = text
	}
	switch r.Strategy {
	case "keep":
		return col, nil
	case "null":
		if c.NotNull {
			return "", fmt.Errorf("column is NOT NULL; use static or another strategy instead of null")
		}
		return "NULL" + cast, nil
	case "static":
		return fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL ELSE %s%s END", col, quoteLiteral(*r.Value), cast), nil
	case "hash", "fake_email", "fake_phone_th", "fake_thai_id", "fake_card", "fake_ip", "fake_address_th", "redact":
		return fmt.Sprintf("pgsafe_mask.%s(%s)%s", r.Strategy, text, cast), nil
	case "fake_name_th", "fake_name_en":
		part := r.Part
		if part == "" {
			part = "full"
		}
		return fmt.Sprintf("pgsafe_mask.%s(%s, %s)%s", r.Strategy, text, quoteLiteral(part), cast), nil
	case "date_shift":
		if !isDateish(c.Type) {
			return "", fmt.Errorf("date_shift needs a date or timestamp column (got %s)", c.Type)
		}
		days := r.MaxDays
		if days == 0 {
			days = 180
		}
		return fmt.Sprintf("(%s + pgsafe_mask.shift_days(%s, %d) * interval '1 day')%s", col, key, days, cast), nil
	case "number_noise":
		return fmt.Sprintf("(%s::numeric * pgsafe_mask.noise_factor(%s, %g))%s", col, key, r.Pct, cast), nil
	case "json_mask":
		keys, err := json.Marshal(r.Keys)
		if err != nil {
			return "", err
		}
		switch {
		case isJSONB(c.Type):
			return fmt.Sprintf("pgsafe_mask.json_mask(%s, %s::jsonb)", col, quoteLiteral(string(keys))), nil
		case isJSON(c.Type):
			return fmt.Sprintf("pgsafe_mask.json_mask(%s::jsonb, %s::jsonb)::json", col, quoteLiteral(string(keys))), nil
		default:
			return "", fmt.Errorf("json_mask needs a json or jsonb column (got %s)", c.Type)
		}
	case "sql":
		return "(" + r.Expr + ")" + cast, nil
	}
	return "", fmt.Errorf("strategy %s cannot be applied to a column", r.Strategy)
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Prepare computes expressions; it fails on rules that cannot apply to the column.
func (p *TablePlan) Prepare() error {
	p.rowKey = rowKeyExpr(p.PK)
	p.exprs = map[string]string{}
	byName := map[string]Col{}
	for _, c := range p.Cols {
		byName[c.Name] = c
	}
	for name, r := range p.Rules {
		c, ok := byName[name]
		if !ok {
			continue
		}
		if c.Generated {
			return fmt.Errorf("%s.%s is a generated column; mask the columns it is computed from instead", p.Table.Qualified(), name)
		}
		e, err := Expr(c, r, p.rowKey)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", p.Table.Qualified(), name, err)
		}
		p.exprs[name] = e
	}
	return nil
}

// MaskedColumns returns the columns this plan changes, sorted.
func (p *TablePlan) MaskedColumns() []string {
	out := make([]string, 0, len(p.exprs))
	for c := range p.exprs {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Statements returns the SQL to run, in order, inside one transaction.
func (p *TablePlan) Statements() []string {
	t := p.Table.Ident()
	switch p.Path {
	case PathTruncate:
		return []string{"TRUNCATE " + t}
	case PathUpdate:
		var sets []string
		for _, c := range p.Cols {
			if e, ok := p.exprs[c.Name]; ok {
				sets = append(sets, c.ident()+" = "+e)
			}
		}
		return []string{"UPDATE " + t + " SET " + strings.Join(sets, ", ")}
	case PathCTAS:
		tmp := pgx.Identifier{Schema, "ctas_" + fmt.Sprint(p.Table.OID)}.Sanitize()
		var sel, cols []string
		for _, c := range p.Cols {
			if c.Generated {
				continue
			}
			e, ok := p.exprs[c.Name]
			if !ok {
				e = c.ident()
			}
			sel = append(sel, e+" AS "+c.ident())
			cols = append(cols, c.ident())
		}
		list := strings.Join(cols, ", ")
		return []string{
			"CREATE UNLOGGED TABLE " + tmp + " AS SELECT " + strings.Join(sel, ", ") + " FROM " + t,
			"TRUNCATE " + t,
			"INSERT INTO " + t + " (" + list + ") OVERRIDING SYSTEM VALUE SELECT " + list + " FROM " + tmp,
			"DROP TABLE " + tmp,
		}
	}
	return nil
}
