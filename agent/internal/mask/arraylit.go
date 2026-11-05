package mask

import "strings"

// pgArrayEscaper escapes an element for a double-quoted PostgreSQL array
// element, then doubles single quotes because the literal sits inside a
// single-quoted SQL string.
var pgArrayEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "'", "''")

// arrayLiteral renders a PostgreSQL text[] literal: {"a","b"}.
func arrayLiteral(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = "\"" + pgArrayEscaper.Replace(v) + "\""
	}
	return "{" + strings.Join(q, ",") + "}"
}
