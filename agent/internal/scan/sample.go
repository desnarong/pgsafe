package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

// ColumnMeta is a column definition read from the catalog.
type ColumnMeta struct {
	Table     pg.Table
	Name      string
	Type      string
	Comment   string
	Generated bool
}

func (c ColumnMeta) Key() string { return c.Table.Qualified() + "." + c.Name }

// ListColumns returns the columns of tables in column order.
func ListColumns(ctx context.Context, q pg.Querier, tables []pg.Table) ([]ColumnMeta, error) {
	byOID := map[uint32]pg.Table{}
	oids := make([]uint32, 0, len(tables))
	for _, t := range tables {
		byOID[t.OID] = t
		oids = append(oids, t.OID)
	}
	if len(oids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		select a.attrelid, a.attname, format_type(a.atttypid, a.atttypmod),
		       coalesce(col_description(a.attrelid, a.attnum), ''), a.attgenerated <> ''
		from pg_attribute a
		where a.attrelid = any($1::oid[]) and a.attnum > 0 and not a.attisdropped
		order by a.attrelid, a.attnum`, oids)
	if err != nil {
		return nil, fmt.Errorf("list columns: %w", err)
	}
	var out []ColumnMeta
	for rows.Next() {
		var oid uint32
		var c ColumnMeta
		if err := rows.Scan(&oid, &c.Name, &c.Type, &c.Comment, &c.Generated); err != nil {
			rows.Close()
			return nil, err
		}
		c.Table = byOID[oid]
		out = append(out, c)
	}
	return out, rows.Err()
}

// Options control a scan.
type Options struct {
	SampleSize int             // max non-null values per column (default 1000)
	Only       map[string]bool // if non-nil, only these "schema.table.column" keys
	ReadOnly   bool            // scanning a live source: read-only tx + statement timeout
}

// Result of a scan. Findings carry no data values.
type Result struct {
	Tables   int       `json:"tables"`
	Columns  int       `json:"columns"`
	Findings []Finding `json:"findings"`
}

// Run samples and classifies columns of tables.
func Run(ctx context.Context, conn *pgx.Conn, tables []pg.Table, o Options) (*Result, error) {
	if o.SampleSize <= 0 {
		o.SampleSize = 1000
	}
	var q pg.Querier = conn
	if o.ReadOnly {
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(context.WithoutCancel(ctx))
		if _, err := tx.Exec(ctx, "set local statement_timeout = '60s'"); err != nil {
			return nil, err
		}
		q = tx
	}
	cols, err := ListColumns(ctx, q, tables)
	if err != nil {
		return nil, err
	}
	byTable := map[string][]ColumnMeta{}
	var order []pg.Table
	res := &Result{Tables: len(tables), Findings: []Finding{}}
	for _, c := range cols {
		if c.Generated || (o.Only != nil && !o.Only[c.Key()]) {
			continue
		}
		res.Columns++
		k := c.Table.Qualified()
		if _, ok := byTable[k]; !ok {
			order = append(order, c.Table)
		}
		byTable[k] = append(byTable[k], c)
	}
	for _, t := range order {
		tcols := byTable[t.Qualified()]
		samples, err := sampleTable(ctx, q, t, tcols, o.SampleSize)
		if err != nil {
			return nil, err
		}
		for i, c := range tcols {
			f, ok := Classify(Column{Table: t.Qualified(), Name: c.Name, Type: c.Type, Comment: c.Comment, Samples: samples[i]})
			if ok {
				res.Findings = append(res.Findings, f)
			}
		}
	}
	SortFindings(res.Findings)
	return res, nil
}

// sampleTable reads up to n non-null text renderings per column in one pass.
// Large analyzed tables are sampled with TABLESAMPLE SYSTEM to avoid full scans.
func sampleTable(ctx context.Context, q pg.Querier, t pg.Table, cols []ColumnMeta, n int) ([][]string, error) {
	out := make([][]string, len(cols))
	var exprs []string
	var idx []int
	for i, c := range cols {
		if NeedsSamples(c.Name, c.Type, c.Comment) {
			exprs = append(exprs, pgx.Identifier{c.Name}.Sanitize()+"::text")
			idx = append(idx, i)
		}
	}
	if len(exprs) == 0 {
		return out, nil
	}
	rowsWanted := n * 5
	sample := ""
	if t.RelTuples > float64(rowsWanted)*2 {
		sample = fmt.Sprintf(" tablesample system (%.4f)", min(100, float64(rowsWanted)*2/t.RelTuples*100))
	}
	sql := fmt.Sprintf("select %s from %s%s limit %d", strings.Join(exprs, ", "), t.Ident(), sample, rowsWanted)
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("sample %s: %w", t.Qualified(), err)
	}
	defer rows.Close()
	vals := make([]*string, len(exprs))
	dest := make([]any, len(exprs))
	for i := range vals {
		dest[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		for j, v := range vals {
			if v != nil && *v != "" && len(out[idx[j]]) < n {
				out[idx[j]] = append(out[idx[j]], *v)
			}
		}
	}
	return out, rows.Err()
}
