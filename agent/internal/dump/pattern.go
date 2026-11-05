package dump

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

// Pattern is a table pattern from exclude_tables / exclude_table_data:
// "name", "schema.name", with * and ? wildcards. Without a schema it matches
// the name in any schema. pgsafe resolves patterns itself and hands pg_dump
// exact quoted names, so what the manifest records always equals what is dumped.
type Pattern struct {
	raw          string
	schema, name *regexp.Regexp
}

func CompilePattern(p string) (Pattern, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return Pattern{}, fmt.Errorf("empty table pattern")
	}
	out := Pattern{raw: p}
	schema, name, qualified := strings.Cut(p, ".")
	if !qualified {
		name, schema = schema, ""
	}
	if name == "" || strings.Contains(name, ".") {
		return Pattern{}, fmt.Errorf("invalid table pattern %q", p)
	}
	out.name = globRe(name)
	if qualified {
		out.schema = globRe(schema)
	}
	return out, nil
}

func globRe(g string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func (p Pattern) Match(schema, name string) bool {
	if p.schema != nil && !p.schema.MatchString(schema) {
		return false
	}
	return p.name.MatchString(name)
}

func (p Pattern) String() string { return p.raw }

// CompilePatterns compiles all patterns.
func CompilePatterns(ps []string) ([]Pattern, error) {
	out := make([]Pattern, 0, len(ps))
	for _, p := range ps {
		c, err := CompilePattern(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// MatchAny reports whether t matches any pattern.
func MatchAny(ps []Pattern, t pg.Table) bool {
	for _, p := range ps {
		if p.Match(t.Schema, t.Name) {
			return true
		}
	}
	return false
}

// quotePattern turns an exact identifier into a pg_dump pattern that matches
// only itself (inside double quotes, wildcards and dots are literal).
func quotePattern(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// TableArg is the exact pg_dump pattern for one table.
func TableArg(t pg.Table) string { return quotePattern(t.Schema) + "." + quotePattern(t.Name) }
