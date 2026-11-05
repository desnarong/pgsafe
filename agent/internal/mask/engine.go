package mask

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/scan"
)

// ErrBlocked is returned when unreviewed PII stops the run (exit 3).
var ErrBlocked = errors.New("masking blocked: columns need review")

// ErrPostCheck is returned when masked data fails verification (exit 1).
var ErrPostCheck = errors.New("post-check failed")

// Options configure Run.
type Options struct {
	Rules          *Rules
	Salt           string
	Policy         string
	LargeTableRows int64
	SampleSize     int
	Jobs           int
	Logger         *slog.Logger
}

// TableReport describes how one table was masked.
type TableReport struct {
	Table      string   `json:"table"`
	Path       string   `json:"path"`
	Columns    []string `json:"columns,omitempty"`
	Rows       int64    `json:"rows"`
	DurationMS int64    `json:"duration_ms"`
}

// Check is a post-check result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // passed | failed
	Detail string `json:"detail,omitempty"`
}

// Report is written as mask.json next to the masked dump. Metadata only.
type Report struct {
	Status       string        `json:"status"` // passed | blocked | failed
	Decision     *Decision     `json:"drift"`
	Tables       []TableReport `json:"tables"`
	FKsValidated int           `json:"fks_validated"`
	PostChecks   []Check       `json:"post_checks"`
	DurationMS   int64         `json:"duration_ms"`
}

// Run masks the database at ci in place. The connection must be a superuser
// (session_replication_role) — the docker scratch runtime is.
func Run(ctx context.Context, ci *pg.ConnInfo, o Options) (*Report, error) {
	start := time.Now()
	log := o.Logger
	rep := &Report{Status: "failed", Tables: []TableReport{}, PostChecks: []Check{}}
	defer func() { rep.DurationMS = time.Since(start).Milliseconds() }()

	conn, err := pg.Connect(ctx, ci)
	if err != nil {
		return rep, err
	}
	defer conn.Close(context.WithoutCancel(ctx))

	tables, err := pg.ListTables(ctx, conn)
	if err != nil {
		return rep, err
	}
	cols, err := scan.ListColumns(ctx, conn, tables)
	if err != nil {
		return rep, err
	}
	existing := map[string]bool{}
	for _, c := range cols {
		existing[c.Key()] = true
	}

	// 1. Drift check: scan every column that has no rule, on the restored data.
	unknown := map[string]bool{}
	for _, c := range cols {
		if !c.Generated && !o.Rules.Has(c.Table.Qualified(), c.Name) {
			unknown[c.Key()] = true
		}
	}
	var findings []scan.Finding
	if len(unknown) > 0 {
		res, err := scan.Run(ctx, conn, tables, scan.Options{SampleSize: o.SampleSize, Only: unknown})
		if err != nil {
			return rep, fmt.Errorf("drift scan: %w", err)
		}
		findings = res.Findings
	}
	d := Decide(o.Rules, existing, findings, o.Policy)
	rep.Decision = d
	for _, w := range d.Warnings {
		log.Warn("masking: " + w)
	}
	if len(d.Blocked) > 0 {
		rep.Status = "blocked"
		return rep, ErrBlocked
	}

	// 2. Plans.
	byTable := map[string]pg.Table{}
	for _, t := range tables {
		byTable[t.Qualified()] = t
	}
	colsByTable := map[string][]Col{}
	for _, c := range cols {
		k := c.Table.Qualified()
		colsByTable[k] = append(colsByTable[k], Col{Name: c.Name, Type: c.Type, Generated: c.Generated})
	}
	if err := fillNotNull(ctx, conn, tables, colsByTable); err != nil {
		return rep, err
	}
	pks, err := primaryKeys(ctx, conn, tables)
	if err != nil {
		return rep, err
	}
	var plans []*TablePlan
	for tname, trules := range d.Effective {
		t, ok := byTable[tname]
		if !ok {
			continue
		}
		p := &TablePlan{Table: t, Cols: colsByTable[tname], PK: pks[t.OID], Rules: map[string]Rule{}}
		if r, ok := trules[TableKey]; ok && r.Strategy == "truncate" {
			p.Path = PathTruncate
		} else {
			for c, r := range trules {
				if c != TableKey && r.Strategy != "keep" {
					p.Rules[c] = r
				}
			}
			if len(p.Rules) == 0 {
				continue
			}
		}
		if err := p.Prepare(); err != nil {
			return rep, err
		}
		if p.Rows, err = pg.ExactCount(ctx, conn, t); err != nil {
			return rep, err
		}
		if p.Path == "" {
			p.Path = PathUpdate
			if o.LargeTableRows > 0 && p.Rows > o.LargeTableRows {
				p.Path = PathCTAS
			}
		}
		plans = append(plans, p)
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Rows > plans[j].Rows }) // biggest first

	// 3. Install functions (keyed by the salt) and sample originals for the post-check.
	if err := Install(ctx, conn, o.Salt); err != nil {
		return rep, err
	}
	defer func() {
		if err := Uninstall(context.WithoutCancel(ctx), conn); err != nil {
			log.Warn("could not drop pgsafe_mask schema", "err", err)
		}
	}()
	if err := sampleOriginals(ctx, conn, plans, o.SampleSize); err != nil {
		return rep, err
	}

	// 4. Drop foreign keys touching masked tables; mask in parallel; re-add and validate.
	fks, err := foreignKeys(ctx, conn, plans)
	if err != nil {
		return rep, err
	}
	for _, fk := range fks {
		if _, err := conn.Exec(ctx, "ALTER TABLE "+fk.table+" DROP CONSTRAINT "+pgx.Identifier{fk.name}.Sanitize()); err != nil {
			return rep, fmt.Errorf("drop foreign key %s: %w", fk.name, err)
		}
	}
	log.Info("masking", "tables", len(plans), "foreign_keys", len(fks))
	reports, err := maskParallel(ctx, ci, plans, o.Jobs)
	rep.Tables = reports
	if err != nil {
		return rep, err
	}
	for _, fk := range fks {
		def := fk.def
		if !strings.HasSuffix(def, "NOT VALID") {
			def += " NOT VALID"
		}
		if _, err := conn.Exec(ctx, "ALTER TABLE "+fk.table+" ADD CONSTRAINT "+pgx.Identifier{fk.name}.Sanitize()+" "+def); err != nil {
			return rep, fmt.Errorf("re-add foreign key %s: %w", fk.name, err)
		}
	}
	fkFailed := []string{}
	for _, fk := range fks {
		if !fk.validated {
			continue
		}
		if _, err := conn.Exec(ctx, "ALTER TABLE "+fk.table+" VALIDATE CONSTRAINT "+pgx.Identifier{fk.name}.Sanitize()); err != nil {
			fkFailed = append(fkFailed, fk.name+": "+firstLine(err.Error()))
			continue
		}
		rep.FKsValidated++
	}
	if len(fkFailed) > 0 {
		rep.PostChecks = append(rep.PostChecks, Check{Name: "foreign_keys", Status: "failed", Detail: strings.Join(fkFailed, "; ")})
	} else {
		rep.PostChecks = append(rep.PostChecks, Check{Name: "foreign_keys", Status: "passed", Detail: fmt.Sprintf("%d validated", rep.FKsValidated)})
	}

	// 5. Post-checks on the masked data.
	checks, err := postCheck(ctx, conn, plans, o.SampleSize)
	if err != nil {
		return rep, err
	}
	rep.PostChecks = append(rep.PostChecks, checks...)
	for _, c := range rep.PostChecks {
		if c.Status != "passed" {
			return rep, fmt.Errorf("%w: %s: %s", ErrPostCheck, c.Name, c.Detail)
		}
	}
	rep.Status = "passed"
	return rep, nil
}

func fillNotNull(ctx context.Context, conn *pgx.Conn, tables []pg.Table, cols map[string][]Col) error {
	oids := make([]uint32, len(tables))
	name := map[uint32]string{}
	for i, t := range tables {
		oids[i] = t.OID
		name[t.OID] = t.Qualified()
	}
	rows, err := conn.Query(ctx, `select attrelid, attname from pg_attribute where attrelid = any($1::oid[]) and attnum > 0 and attnotnull and not attisdropped`, oids)
	if err != nil {
		return err
	}
	nn := map[string]bool{}
	for rows.Next() {
		var oid uint32
		var c string
		if err := rows.Scan(&oid, &c); err != nil {
			return err
		}
		nn[name[oid]+"."+c] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for t, cs := range cols {
		for i := range cs {
			cs[i].NotNull = nn[t+"."+cs[i].Name]
		}
	}
	return nil
}

func primaryKeys(ctx context.Context, conn *pgx.Conn, tables []pg.Table) (map[uint32][]string, error) {
	oids := make([]uint32, len(tables))
	for i, t := range tables {
		oids[i] = t.OID
	}
	rows, err := conn.Query(ctx, `
		select i.indrelid, a.attname
		from pg_index i
		join lateral unnest(i.indkey) with ordinality k(attnum, ord) on true
		join pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.attnum
		where i.indisprimary and i.indrelid = any($1::oid[])
		order by i.indrelid, k.ord`, oids)
	if err != nil {
		return nil, fmt.Errorf("read primary keys: %w", err)
	}
	out := map[uint32][]string{}
	for rows.Next() {
		var oid uint32
		var c string
		if err := rows.Scan(&oid, &c); err != nil {
			return nil, err
		}
		out[oid] = append(out[oid], c)
	}
	return out, rows.Err()
}

type foreignKey struct {
	table, name, def string
	validated        bool
}

func foreignKeys(ctx context.Context, conn *pgx.Conn, plans []*TablePlan) ([]foreignKey, error) {
	oids := make([]uint32, len(plans))
	for i, p := range plans {
		oids[i] = p.Table.OID
	}
	if len(oids) == 0 {
		return nil, nil
	}
	rows, err := conn.Query(ctx, `
		select format('%I.%I', n.nspname, r.relname), c.conname, pg_get_constraintdef(c.oid), c.convalidated
		from pg_constraint c
		join pg_class r on r.oid = c.conrelid
		join pg_namespace n on n.oid = r.relnamespace
		where c.contype = 'f' and (c.conrelid = any($1::oid[]) or c.confrelid = any($1::oid[]))
		order by 1, 2`, oids)
	if err != nil {
		return nil, fmt.Errorf("read foreign keys: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (foreignKey, error) {
		var fk foreignKey
		err := r.Scan(&fk.table, &fk.name, &fk.def, &fk.validated)
		return fk, err
	})
}

// maskParallel runs each plan in its own transaction on its own connection.
func maskParallel(ctx context.Context, ci *pg.ConnInfo, plans []*TablePlan, jobs int) ([]TableReport, error) {
	if jobs <= 0 {
		jobs = min(4, runtime.NumCPU())
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan int)
	reports := make([]TableReport, len(plans))
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for w := 0; w < min(jobs, max(len(plans), 1)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := pg.Connect(ctx, ci)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				cancel()
				return
			}
			defer conn.Close(context.WithoutCancel(ctx))
			// Triggers (and the remaining RI triggers) must not fire while masking.
			_, err = conn.Exec(ctx, "SET session_replication_role = replica; SET max_parallel_workers_per_gather = 4")
			for i := range work {
				if err == nil {
					reports[i], err = maskTable(ctx, conn, plans[i])
				}
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					cancel()
				}
			}
		}()
	}
	for i := range plans {
		select {
		case work <- i:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		if strings.Contains(firstErr.Error(), "session_replication_role") {
			return reports, fmt.Errorf("masking needs a superuser on the scratch database (session_replication_role): %w", firstErr)
		}
		return reports, firstErr
	}
	return reports, ctx.Err()
}

func maskTable(ctx context.Context, conn *pgx.Conn, p *TablePlan) (TableReport, error) {
	t0 := time.Now()
	rep := TableReport{Table: p.Table.Qualified(), Path: p.Path, Columns: p.MaskedColumns(), Rows: p.Rows}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return rep, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	for _, stmt := range p.Statements() {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return rep, fmt.Errorf("mask %s (%s): %s", p.Table.Qualified(), p.Path, firstLine(err.Error()))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return rep, err
	}
	rep.DurationMS = time.Since(t0).Milliseconds()
	return rep, nil
}
