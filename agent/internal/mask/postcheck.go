package mask

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/scan"
)

// How much of a sampled column may legitimately keep its original value.
// Format-preserving and hash strategies essentially never map a value to
// itself; dictionary picks can (a real "สมชาย" may draw "สมชาย").
var unchangedTolerance = map[string]float64{
	"hash": 0, "fake_email": 0, "fake_thai_id": 0, "fake_phone_th": 0, "fake_card": 0, "fake_ip": 0,
	"fake_name_th": 0.02, "fake_name_en": 0.02, "fake_address_th": 0.02,
}

// Strategies whose outputs can never equal any real input: safe to compare
// against the whole table when there is no primary key.
var disjointOutput = map[string]bool{"hash": true, "fake_email": true}

func valueHash(col string) string { return "sha256(convert_to(" + col + "::text, 'UTF8'))" }

// sampleOriginals stores hashes (never values) of up to n original values per
// checked column, keyed by primary key when there is one.
func sampleOriginals(ctx context.Context, conn *pgx.Conn, plans []*TablePlan, n int) error {
	if n <= 0 {
		return nil
	}
	for _, p := range plans {
		for _, c := range p.MaskedColumns() {
			s := p.Rules[c].Strategy
			if _, ok := unchangedTolerance[s]; !ok {
				continue
			}
			if p.rowKey == "" && !disjointOutput[s] {
				continue
			}
			col := pgx.Identifier{c}.Sanitize()
			key := "NULL"
			if p.rowKey != "" {
				key = p.rowKey
			}
			sql := fmt.Sprintf(`INSERT INTO pgsafe_mask.orig_sample (tbl, col, row_key, value_hash)
				SELECT $1, $2, %s, %s FROM %s WHERE %s IS NOT NULL LIMIT %d`, key, valueHash(col), p.Table.Ident(), col, n)
			if _, err := conn.Exec(ctx, sql, p.Table.Qualified(), c); err != nil {
				return fmt.Errorf("sample %s.%s: %w", p.Table.Qualified(), c, err)
			}
		}
	}
	return nil
}

// postCheck verifies the masked data.
func postCheck(ctx context.Context, conn *pgx.Conn, plans []*TablePlan, n int) ([]Check, error) {
	var unchanged, nonNull, leaked, rowsBad []string
	checkedCols := 0
	for _, p := range plans {
		t := p.Table.Ident()
		// Row counts: masking never adds or loses rows (CTAS path included).
		got, err := pg.ExactCount(ctx, conn, p.Table)
		if err != nil {
			return nil, err
		}
		want := p.Rows
		if p.Path == PathTruncate {
			want = 0
		}
		if got != want {
			rowsBad = append(rowsBad, fmt.Sprintf("%s: %d rows, expected %d", p.Table.Qualified(), got, want))
		}

		for _, c := range p.MaskedColumns() {
			r := p.Rules[c]
			col := pgx.Identifier{c}.Sanitize()
			key := p.Table.Qualified() + "." + c
			switch {
			case r.Strategy == "null":
				var cnt int64
				if err := conn.QueryRow(ctx, "select count(*) from "+t+" where "+col+" is not null").Scan(&cnt); err != nil {
					return nil, err
				}
				checkedCols++
				if cnt > 0 {
					nonNull = append(nonNull, fmt.Sprintf("%s: %d non-null", key, cnt))
				}
			case r.Strategy == "redact":
				rows, err := conn.Query(ctx, fmt.Sprintf("select %s::text from %s where %s is not null limit %d", col, t, col, max(n, 1)))
				if err != nil {
					return nil, err
				}
				bad := 0
				for rows.Next() {
					var v string
					if err := rows.Scan(&v); err != nil {
						rows.Close()
						return nil, err
					}
					if scan.ContainsPII(v) {
						bad++
					}
				}
				if err := rows.Err(); err != nil {
					return nil, err
				}
				checkedCols++
				if bad > 0 {
					leaked = append(leaked, fmt.Sprintf("%s: PII patterns remain in %d sampled rows", key, bad))
				}
			default:
				tol, ok := unchangedTolerance[r.Strategy]
				if !ok {
					continue
				}
				var same, total int64
				var err error
				if p.rowKey != "" {
					err = conn.QueryRow(ctx, fmt.Sprintf(`
						select count(*) filter (where s.value_hash = %s), count(*)
						from pgsafe_mask.orig_sample s join %s x on (%s) = s.row_key
						where s.tbl = $1 and s.col = $2`, valueHash("x."+col), t, prefixed(p.rowKey, "x.")),
						p.Table.Qualified(), c).Scan(&same, &total)
				} else if disjointOutput[r.Strategy] {
					err = conn.QueryRow(ctx, fmt.Sprintf(`
						select count(*), (select count(*) from pgsafe_mask.orig_sample where tbl = $1 and col = $2)
						from %s where %s in (select value_hash from pgsafe_mask.orig_sample where tbl = $1 and col = $2)`,
						t, valueHash(col)), p.Table.Qualified(), c).Scan(&same, &total)
				} else {
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("post-check %s: %w", key, err)
				}
				checkedCols++
				if total > 0 && float64(same) > float64(total)*tol {
					unchanged = append(unchanged, fmt.Sprintf("%s: %d of %d sampled values unchanged", key, same, total))
				}
			}
		}
	}
	status := func(bad []string, ok string) Check {
		if len(bad) > 0 {
			return Check{Status: "failed", Detail: strings.Join(bad, "; ")}
		}
		return Check{Status: "passed", Detail: ok}
	}
	out := []Check{}
	c := status(unchanged, fmt.Sprintf("%d columns checked", checkedCols))
	c.Name = "values_changed"
	out = append(out, c)
	c = status(leaked, "no PII patterns in redacted text")
	c.Name = "redacted_text"
	out = append(out, c)
	c = status(nonNull, "")
	c.Name = "null_columns"
	out = append(out, c)
	c = status(rowsBad, fmt.Sprintf("%d tables", len(plans)))
	c.Name = "row_counts"
	out = append(out, c)
	return out, nil
}

// prefixed qualifies the quoted column references in a rowKey expression.
func prefixed(rowKey, alias string) string {
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(rowKey); i++ {
		ch := rowKey[i]
		if ch == '"' {
			if !inQuote {
				b.WriteString(alias)
			} else if i+1 < len(rowKey) && rowKey[i+1] == '"' { // escaped quote inside identifier
				b.WriteString(`""`)
				i++
				continue
			}
			inQuote = !inQuote
		}
		b.WriteByte(ch)
	}
	return b.String()
}
