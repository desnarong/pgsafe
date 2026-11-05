package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ids"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/restore"
	"github.com/desnarong/pgsafe/agent/internal/scratch"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

// Check names, in the order they run.
const (
	CheckChecksum      = "checksum"
	CheckDecrypt       = "decrypt"
	CheckRestore       = "restore"
	CheckTablesPresent = "tables_present"
	CheckRowCounts     = "row_counts"
	CheckNonEmpty      = "non_empty"
	CheckSchemaHash    = "schema_hash"
	customPrefix       = "sql:"
)

type Options struct {
	Config       *config.Config
	Database     config.Database
	Store        *storage.Store
	Runtime      scratch.Runtime
	BackupID     string // empty = newest
	RunID        string
	Logger       *slog.Logger
	AgentVersion string
}

// Run verifies one backup by restoring it into a scratch database. It returns
// the report (also written to verify.json) whenever a backup was found; err is
// non-nil when verification could not run at all.
func Run(ctx context.Context, o Options) (*manifest.VerifyReport, error) {
	cfg, log := o.Config, o.Logger.With("db", o.Database.Name, "run_id", o.RunID)

	var identities []age.Identity
	m, err := o.Store.FindBackup(ctx, o.Database.Name, o.BackupID)
	if err != nil {
		return nil, err
	}
	if m.Encryption == "age" {
		if err := cfg.Require(map[string]string{"encryption.identity_file": cfg.Encryption.IdentityFile}); err != nil {
			return nil, exitcode.Config(fmt.Errorf("verify needs the age private key to decrypt the backup: %w", err))
		}
		if identities, err = crypto.LoadIdentities(cfg.Resolve(cfg.Encryption.IdentityFile)); err != nil {
			return nil, exitcode.Config(err)
		}
	}
	log = log.With("backup_id", m.BackupID)

	start := time.Now().UTC()
	rep := &manifest.VerifyReport{
		BackupID: m.BackupID, Database: m.Database, RunID: o.RunID, Status: manifest.StatusPassed,
		StartedAt: start, Runtime: o.Runtime.Name(), TablesTotal: len(m.Tables), AgentVersion: o.AgentVersion,
		Manifest: m,
	}
	v := &run{ctx: ctx, o: o, m: m, rep: rep, log: log}
	runErr := v.execute(identities)
	if runErr != nil {
		rep.Status = manifest.StatusError
		rep.Error = runErr.Error()
	}
	rep.FinishedAt = time.Now().UTC()
	rep.DurationMS = rep.FinishedAt.Sub(start).Milliseconds()

	// Persist the report even when cancelled, so `list backups` reflects it.
	wctx, cancel := scratch.DestroyContext(ctx)
	defer cancel()
	if data, err := rep.Marshal(); err == nil {
		if err := o.Store.PutBytes(wctx, storage.ObjectKey(m.Database, m.BackupID, manifest.VerifyFileName), data, "application/json"); err != nil {
			log.Warn("could not write verify.json", "err", err)
		}
	}
	return rep, runErr
}

type run struct {
	ctx context.Context
	o   Options
	m   *manifest.Manifest
	rep *manifest.VerifyReport
	log *slog.Logger
}

func (v *run) add(name, status, format string, a ...any) {
	v.rep.Checks = append(v.rep.Checks, manifest.CheckResult{Name: name, Status: status, Detail: fmt.Sprintf(format, a...)})
	if status == manifest.StatusFailed && v.rep.Status == manifest.StatusPassed {
		v.rep.Status = manifest.StatusFailed
	}
}

func (v *run) execute(identities []age.Identity) error {
	ctx, m := v.ctx, v.m
	tmp, err := os.MkdirTemp("", "pgsafe-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	// 1–2. checksum of the stored object, then decrypt
	obj := restore.Object{Key: storage.ObjectKey(m.Database, m.BackupID, m.Object), SHA256: m.SHA256,
		SizeBytes: m.SizeBytes, Encrypted: identities != nil}
	fr, err := restore.Fetch(ctx, v.o.Store, obj, identities, tmp)
	switch {
	case errors.Is(err, restore.ErrChecksum):
		v.add(CheckChecksum, manifest.StatusFailed, "%s", strings.TrimPrefix(err.Error(), restore.ErrChecksum.Error()+": "))
		return nil
	case errors.Is(err, restore.ErrDecrypt):
		v.add(CheckChecksum, manifest.StatusPassed, "sha256 %s… (%d bytes)", short(fr.SHA256), fr.SizeBytes)
		v.add(CheckDecrypt, manifest.StatusFailed, "%s", strings.TrimPrefix(err.Error(), restore.ErrDecrypt.Error()+": "))
		return nil
	case err != nil:
		return err
	}
	v.add(CheckChecksum, manifest.StatusPassed, "sha256 %s… (%d bytes)", short(fr.SHA256), fr.SizeBytes)
	if identities != nil {
		v.add(CheckDecrypt, manifest.StatusPassed, "age")
	}

	// 3. scratch + restore
	inst, err := v.o.Runtime.Start(ctx, scratch.StartOptions{
		RunID: ids.Short(v.o.RunID), Database: v.o.Database.Name, Major: m.PGServerMajor, WorkDir: tmp, DumpBytes: m.SizeBytes,
	})
	if err != nil {
		return fmt.Errorf("start scratch: %w", err)
	}
	defer func() {
		dctx, cancel := scratch.DestroyContext(ctx)
		defer cancel()
		if err := inst.Destroy(dctx); err != nil {
			v.log.Error("scratch cleanup failed", "scratch", inst.Describe(), "err", err)
		}
	}()
	v.log.Info("restoring into scratch", "scratch", inst.Describe())

	jobs := restore.DefaultJobs(v.o.Config.Verify.Jobs)
	rr := restore.Restore(ctx, inst, jobs)
	v.rep.RestoreDurationMS = rr.Duration.Milliseconds()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !rr.OK() {
		// Keep going: the data checks show how much of the restore is usable.
		v.add(CheckRestore, manifest.StatusFailed, "%s", rr.Detail())
	} else {
		v.add(CheckRestore, manifest.StatusPassed, "pg_restore ok in %s (jobs=%d)", rr.Duration.Round(time.Millisecond), jobs)
	}

	conn, err := pg.Connect(ctx, inst.ConnInfo())
	if err != nil {
		return fmt.Errorf("connect to scratch: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return v.checkData(conn)
}

func (v *run) checkData(conn *pgx.Conn) error {
	ctx, m := v.ctx, v.m
	restored, err := pg.ListTables(ctx, conn)
	if err != nil {
		return err
	}
	byName := make(map[string]pg.Table, len(restored))
	for _, t := range restored {
		byName[t.Qualified()] = t
	}

	// 4. tables present
	var missing []string
	var present []pg.Table
	for _, mt := range m.Tables {
		if t, ok := byName[mt.Qualified()]; ok {
			present = append(present, t)
		} else {
			missing = append(missing, mt.Qualified())
		}
	}
	if len(missing) > 0 {
		v.add(CheckTablesPresent, manifest.StatusFailed, "%d/%d tables missing: %s", len(missing), len(m.Tables), strings.Join(first(missing, 10), ", "))
	} else {
		v.add(CheckTablesPresent, manifest.StatusPassed, "%d/%d tables", len(m.Tables), len(m.Tables))
	}

	// 5–6. row counts and non-empty tables
	tol := v.o.Config.Verify.RowCount.EstimateTolerancePct
	var rowBad, emptyBad []string
	ok, exact, est, excluded := 0, 0, 0, 0
	for _, mt := range m.Tables {
		t, found := byName[mt.Qualified()]
		if !found {
			continue
		}
		if mt.DataExcluded {
			excluded++
			ok++
			continue
		}
		got, err := pg.ExactCount(ctx, conn, t)
		if err != nil {
			return err
		}
		good := true
		if !RowsMatch(mt.Rows, got, mt.RowsExact, tol) {
			rowBad = append(rowBad, fmt.Sprintf("%s: %d, manifest %d", mt.Qualified(), got, mt.Rows))
			good = false
		}
		if mt.Rows > 0 && got == 0 {
			emptyBad = append(emptyBad, mt.Qualified())
			good = false
		}
		if mt.RowsExact {
			exact++
		} else {
			est++
		}
		if good {
			ok++
		}
	}
	v.rep.TablesOK = ok
	if len(rowBad) > 0 {
		v.add(CheckRowCounts, manifest.StatusFailed, "%s", strings.Join(first(rowBad, 10), "; "))
	} else {
		v.add(CheckRowCounts, manifest.StatusPassed, "%d exact, %d estimated (±%g%%), %d data excluded", exact, est, tol, excluded)
	}
	if len(emptyBad) > 0 {
		v.add(CheckNonEmpty, manifest.StatusFailed, "empty after restore: %s", strings.Join(first(emptyBad, 10), ", "))
	} else {
		v.add(CheckNonEmpty, manifest.StatusPassed, "")
	}

	// 7. schema hash
	schemas, err := pg.ReadSchema(ctx, conn, present)
	if err != nil {
		return err
	}
	if h := pg.HashSchema(schemas); h != m.SchemaHash {
		v.add(CheckSchemaHash, manifest.StatusFailed, "%s… differs from manifest %s…", short(h), short(m.SchemaHash))
	} else {
		v.add(CheckSchemaHash, manifest.StatusPassed, "%s…", short(h))
	}

	// 8. customer SQL checks
	for _, c := range v.o.Config.Verify.Checks {
		pass, detail := runSQLCheck(ctx, conn, c.Query)
		status := manifest.StatusPassed
		if !pass {
			status = manifest.StatusFailed
		}
		v.add(customPrefix+c.Name, status, "%s", detail)
	}
	return nil
}

// RowsMatch compares a restored count against the manifest. Exact counts must
// be equal; estimates must be within tolPct percent.
func RowsMatch(want, got int64, exact bool, tolPct float64) bool {
	if exact {
		return want == got
	}
	if want == 0 {
		return got == 0
	}
	return math.Abs(float64(got-want)) <= float64(want)*tolPct/100
}

// runSQLCheck runs a customer check read-only; it must return one boolean true.
func runSQLCheck(ctx context.Context, conn *pgx.Conn, query string) (bool, string) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, err.Error()
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, "set local statement_timeout = '5min'"); err != nil {
		return false, err.Error()
	}
	var result *bool
	if err := tx.QueryRow(ctx, query).Scan(&result); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "query returned no rows"
		}
		return false, err.Error()
	}
	if result == nil {
		return false, "query returned NULL"
	}
	if !*result {
		return false, "query returned false"
	}
	return true, "true"
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("(+%d more)", len(s)-n))
	}
	return s
}

// CheckRestored runs the data checks of verify (tables present, row counts,
// non-empty tables, schema hash, custom SQL checks) against a database that
// m was restored into — used after a real restore.
func CheckRestored(ctx context.Context, conn *pgx.Conn, m *manifest.Manifest, cfg *config.Config) ([]manifest.CheckResult, int, error) {
	v := &run{ctx: ctx, o: Options{Config: cfg}, m: m, rep: &manifest.VerifyReport{Status: manifest.StatusPassed, TablesTotal: len(m.Tables)}}
	err := v.checkData(conn)
	return v.rep.Checks, v.rep.TablesOK, err
}
