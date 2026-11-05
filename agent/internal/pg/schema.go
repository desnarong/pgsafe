package pg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Table is a user table (ordinary or partitioned).
type Table struct {
	Schema    string
	Name      string
	OID       uint32
	RelTuples float64 // planner estimate; -1 if never analyzed
}

func (t Table) Qualified() string { return t.Schema + "." + t.Name }

// Ident returns the quoted, schema-qualified identifier for SQL.
func (t Table) Ident() string { return pgx.Identifier{t.Schema, t.Name}.Sanitize() }

// ListTables returns user tables, excluding system schemas and tables that
// belong to extensions (pg_dump does not dump those).
func ListTables(ctx context.Context, q Querier) ([]Table, error) {
	rows, err := q.Query(ctx, `
		select n.nspname, c.relname, c.oid, c.reltuples::float8
		from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		where c.relkind in ('r', 'p')
		  and n.nspname not in ('pg_catalog', 'information_schema')
		  and n.nspname not like 'pg\_toast%' and n.nspname not like 'pg\_temp%'
		  and not exists (
		      select 1 from pg_depend d
		      where d.classid = 'pg_class'::regclass and d.objid = c.oid and d.deptype = 'e')
		order by 1, 2`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Table, error) {
		var t Table
		err := r.Scan(&t.Schema, &t.Name, &t.OID, &t.RelTuples)
		return t, err
	})
}

// TableSchema is the part of a table's definition that schema_hash covers.
type TableSchema struct {
	Qualified   string
	Columns     []string // in column order
	Constraints []string // "name def"
	Indexes     []string // pg_get_indexdef
}

// ReadSchema reads column, constraint and index definitions for tables.
func ReadSchema(ctx context.Context, q Querier, tables []Table) ([]TableSchema, error) {
	byOID := make(map[uint32]*TableSchema, len(tables))
	oids := make([]uint32, 0, len(tables))
	out := make([]TableSchema, len(tables))
	for i, t := range tables {
		out[i].Qualified = t.Qualified()
		byOID[t.OID] = &out[i]
		oids = append(oids, t.OID)
	}
	if len(oids) == 0 {
		return out, nil
	}

	rows, err := q.Query(ctx, `
		select a.attrelid, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       coalesce(pg_get_expr(d.adbin, d.adrelid), ''), a.attidentity::text, a.attgenerated::text
		from pg_attribute a
		left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
		where a.attrelid = any($1::oid[]) and a.attnum > 0 and not a.attisdropped
		order by a.attrelid, a.attnum`, oids)
	if err != nil {
		return nil, fmt.Errorf("read columns: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var name, typ, def, ident, gen string
		var notNull bool
		if err := rows.Scan(&oid, &name, &typ, &notNull, &def, &ident, &gen); err != nil {
			rows.Close()
			return nil, err
		}
		ts := byOID[oid]
		ts.Columns = append(ts.Columns, fmt.Sprintf("%s %s notnull=%t default=%q identity=%q generated=%q", name, typ, notNull, def, ident, gen))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read columns: %w", err)
	}

	// contype 'n' (PG18 not-null constraints) is already covered by attnotnull.
	rows, err = q.Query(ctx, `
		select conrelid, conname, pg_get_constraintdef(oid)
		from pg_constraint
		where conrelid = any($1::oid[]) and contype <> 'n'`, oids)
	if err != nil {
		return nil, fmt.Errorf("read constraints: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var name, def string
		if err := rows.Scan(&oid, &name, &def); err != nil {
			rows.Close()
			return nil, err
		}
		byOID[oid].Constraints = append(byOID[oid].Constraints, name+" "+def)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read constraints: %w", err)
	}

	rows, err = q.Query(ctx, `select indrelid, pg_get_indexdef(indexrelid) from pg_index where indrelid = any($1::oid[])`, oids)
	if err != nil {
		return nil, fmt.Errorf("read indexes: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var def string
		if err := rows.Scan(&oid, &def); err != nil {
			rows.Close()
			return nil, err
		}
		byOID[oid].Indexes = append(byOID[oid].Indexes, def)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read indexes: %w", err)
	}
	return out, nil
}

// HashSchema returns a sha256 over a canonical rendering of the schema.
// Table, constraint and index order do not matter; column order does.
func HashSchema(tables []TableSchema) string {
	ts := make([]TableSchema, len(tables))
	copy(ts, tables)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Qualified < ts[j].Qualified })

	var b strings.Builder
	for _, t := range ts {
		b.WriteString("T " + t.Qualified + "\n")
		for _, c := range t.Columns {
			b.WriteString("  C " + c + "\n")
		}
		for _, c := range sorted(t.Constraints) {
			b.WriteString("  K " + c + "\n")
		}
		for _, i := range sorted(t.Indexes) {
			b.WriteString("  I " + i + "\n")
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// CountRows returns an exact count when the table is small (or has never
// been analyzed) and the planner estimate otherwise.
func CountRows(ctx context.Context, q Querier, t Table, exactBelow int64) (rows int64, exact bool, err error) {
	if t.RelTuples >= 0 && int64(t.RelTuples) >= exactBelow {
		return int64(t.RelTuples), false, nil
	}
	if err := q.QueryRow(ctx, "select count(*) from "+t.Ident()).Scan(&rows); err != nil {
		return 0, false, fmt.Errorf("count %s: %w", t.Qualified(), err)
	}
	return rows, true, nil
}

// ExactCount always runs count(*).
func ExactCount(ctx context.Context, q Querier, t Table) (int64, error) {
	var n int64
	if err := q.QueryRow(ctx, "select count(*) from "+t.Ident()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count %s: %w", t.Qualified(), err)
	}
	return n, nil
}

// Snapshot is an open REPEATABLE READ transaction whose snapshot was exported
// for pg_dump --snapshot, so schema reads and row counts see exactly what is dumped.
type Snapshot struct {
	Tx pgx.Tx
	ID string
}

func ExportSnapshot(ctx context.Context, conn *pgx.Conn) (*Snapshot, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin snapshot transaction: %w", err)
	}
	var id string
	if err := tx.QueryRow(ctx, "select pg_export_snapshot()").Scan(&id); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("export snapshot: %w", err)
	}
	return &Snapshot{Tx: tx, ID: id}, nil
}

// Release ends the snapshot transaction.
func (s *Snapshot) Release(ctx context.Context) error { return s.Tx.Commit(ctx) }

// RoleInfo describes the privileges of the connecting role.
type RoleInfo struct {
	Name        string
	Superuser   bool
	ReadAllData bool
}

func CurrentRole(ctx context.Context, q Querier) (RoleInfo, error) {
	var r RoleInfo
	err := q.QueryRow(ctx, `
		select current_user, r.rolsuper,
		       coalesce((select pg_has_role(current_user, g.oid, 'member') from pg_roles g where g.rolname = 'pg_read_all_data'), false)
		from pg_roles r where r.rolname = current_user`).Scan(&r.Name, &r.Superuser, &r.ReadAllData)
	if err != nil {
		return r, fmt.Errorf("read role: %w", err)
	}
	return r, nil
}
