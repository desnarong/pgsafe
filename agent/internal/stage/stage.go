// Package stage delivers masked dumps (design doc §3.8): replaces a staging
// database with a near-atomic rename swap, keeps preserve_tables, and restores
// masked dumps for developers (pgsafe pull).
package stage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/restore"
)

// SameDatabase reports whether a and b point at the same database on the
// same server (loopback names are treated as equal; default port 5432).
func SameDatabase(a, b *pg.ConnInfo) bool {
	host := func(c *pg.ConnInfo) string {
		if c.IsLoopback() {
			return "loopback"
		}
		return c.Host()
	}
	return host(a) == host(b) && port(a) == port(b) && a.Database() == b.Database()
}

func port(c *pg.ConnInfo) string {
	if p := c.Port(); p != "" {
		return p
	}
	return "5432"
}

// Options for replacing a database.
type Options struct {
	Target         *pg.ConnInfo // the staging (or dev) database to replace
	DumpPath       string       // decrypted masked dump on local disk
	PreserveTables []string     // table patterns to carry over from the current database
	PGClient       string
	DockerImage    string
	Jobs           int
	MustNotExist   bool   // pull without --replace: refuse to touch an existing database
	KeepOld        bool   // restore --replace: keep the previous database renamed instead of dropping it
	Owner          string // configured database name, tagged on the temporary database for cleanup
	Logger         *slog.Logger
}

// Result of a replace.
type Result struct {
	Database   string   `json:"database"`
	Replaced   bool     `json:"replaced"`          // an existing database was swapped out
	KeptAs     string   `json:"kept_as,omitempty"` // KeepOld: name of the previous database
	Preserved  []string `json:"preserved_tables"`
	DurationMS int64    `json:"duration_ms"`
}

// ErrExists is returned when MustNotExist is set and the database exists.
var ErrExists = errors.New("database already exists")

// maintenanceDB is where CREATE/RENAME/DROP DATABASE run from.
const maintenanceDB = "postgres"

// Replace restores DumpPath into a new database and swaps it in for Target.
// The old database keeps serving until the final rename; on any failure the
// new database is dropped and the old one is left untouched.
func Replace(ctx context.Context, o Options) (*Result, error) {
	t0 := time.Now()
	name := o.Target.Database()
	if name == "" || name == maintenanceDB || name == "template0" || name == "template1" {
		return nil, fmt.Errorf("refusing to replace database %q", name)
	}
	res := &Result{Database: name, Preserved: []string{}}
	admin, err := pg.Connect(ctx, o.Target.WithDatabase(maintenanceDB))
	if err != nil {
		return nil, err
	}
	defer admin.Close(context.WithoutCancel(ctx))

	var exists bool
	if err := admin.QueryRow(ctx, "select exists(select 1 from pg_database where datname = $1)", name).Scan(&exists); err != nil {
		return nil, err
	}
	if exists && o.MustNotExist {
		return nil, fmt.Errorf("%s: %w (use --replace to overwrite it)", name, ErrExists)
	}
	ver, err := pg.ServerVersion(ctx, admin)
	if err != nil {
		return nil, err
	}
	client, err := dump.Resolve(ctx, o.PGClient, ver.Major, o.DockerImage)
	if err != nil {
		return nil, err
	}

	suffix := strconv.FormatInt(time.Now().UnixNano()%1e10, 36)
	newName := shorten(name, "_pgsafe_new_"+suffix)
	oldName := shorten(name, "_pgsafe_old_"+suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+ident(newName)); err != nil {
		return nil, fmt.Errorf("create %s: %w", newName, err)
	}
	if o.Owner != "" {
		if _, err := admin.Exec(ctx, "COMMENT ON DATABASE "+ident(newName)+" IS "+quoteLit("pgsafe db="+o.Owner)); err != nil {
			_, _ = admin.Exec(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+ident(newName))
			return nil, fmt.Errorf("tag %s: %w", newName, err)
		}
	}
	swapped := false
	defer func() {
		if !swapped {
			_, _ = admin.Exec(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+ident(newName)+" WITH (FORCE)")
		}
	}()

	newCI := o.Target.WithDatabase(newName)
	if err := runRestore(ctx, client, newCI, o.DumpPath, restore.DefaultJobs(o.Jobs)); err != nil {
		return nil, err
	}

	if exists && len(o.PreserveTables) > 0 {
		kept, err := preserve(ctx, client, o.Target, newCI, o.PreserveTables, filepath.Dir(o.DumpPath))
		if err != nil {
			return nil, err
		}
		res.Preserved = kept
	}

	// Swap: block new connections, kick existing ones, rename old → aside, new → name.
	if exists {
		if _, err := admin.Exec(ctx, "ALTER DATABASE "+ident(name)+" WITH ALLOW_CONNECTIONS false"); err != nil {
			return nil, fmt.Errorf("lock %s: %w", name, err)
		}
		if _, err := admin.Exec(ctx, "select pg_terminate_backend(pid) from pg_stat_activity where datname = $1 and pid <> pg_backend_pid()", name); err != nil {
			_, _ = admin.Exec(ctx, "ALTER DATABASE "+ident(name)+" WITH ALLOW_CONNECTIONS true")
			return nil, err
		}
		if err := retry(ctx, func() error {
			_, err := admin.Exec(ctx, "ALTER DATABASE "+ident(name)+" RENAME TO "+ident(oldName))
			return err
		}); err != nil {
			_, _ = admin.Exec(ctx, "ALTER DATABASE "+ident(name)+" WITH ALLOW_CONNECTIONS true")
			return nil, fmt.Errorf("rename %s: %w", name, err)
		}
	}
	if _, err := admin.Exec(ctx, "ALTER DATABASE "+ident(newName)+" RENAME TO "+ident(name)); err != nil {
		if exists { // put the old one back
			_, _ = admin.Exec(context.WithoutCancel(ctx), "ALTER DATABASE "+ident(oldName)+" RENAME TO "+ident(name))
			_, _ = admin.Exec(context.WithoutCancel(ctx), "ALTER DATABASE "+ident(name)+" WITH ALLOW_CONNECTIONS true")
		}
		return nil, fmt.Errorf("rename %s → %s: %w", newName, name, err)
	}
	swapped = true
	if o.Owner != "" { // the live database is no longer temporary
		_, _ = admin.Exec(ctx, "COMMENT ON DATABASE "+ident(name)+" IS NULL")
	}
	if exists {
		res.Replaced = true
		if o.KeepOld {
			_, _ = admin.Exec(ctx, "ALTER DATABASE "+ident(oldName)+" WITH ALLOW_CONNECTIONS true")
			res.KeptAs = oldName
		} else if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+ident(oldName)+" WITH (FORCE)"); err != nil {
			o.Logger.Warn("could not drop previous database", "database", oldName, "err", err)
		}
	}
	res.DurationMS = time.Since(t0).Milliseconds()
	return res, nil
}

func runRestore(ctx context.Context, client *dump.Client, ci *pg.ConnInfo, file string, jobs int, extra ...string) error {
	cmd := client.RestoreCommand(ctx, ci, file, jobs, extra...)
	stderr := &dump.TailBuffer{Max: 256 << 10}
	cmd.Stderr = stderr
	err := cmd.Run()
	rr := &restore.RestoreResult{Errors: dump.RestoreErrors(dump.Scrub(stderr.String(), ci)), Err: err}
	if !rr.OK() {
		return fmt.Errorf("restore into %s: %s", ci.Database(), rr.Detail())
	}
	return nil
}

// preserve copies the matching tables from the current database into the new
// one, replacing their masked versions.
func preserve(ctx context.Context, client *dump.Client, old, newCI *pg.ConnInfo, patterns []string, workDir string) ([]string, error) {
	pats, err := dump.CompilePatterns(patterns)
	if err != nil {
		return nil, fmt.Errorf("preserve_tables: %w", err)
	}
	conn, err := pg.Connect(ctx, old)
	if err != nil {
		return nil, err
	}
	tables, err := pg.ListTables(ctx, conn)
	conn.Close(context.WithoutCancel(ctx))
	if err != nil {
		return nil, err
	}
	var args, kept []string
	for _, t := range tables {
		if dump.MatchAny(pats, t) {
			args = append(args, "--table="+dump.TableArg(t))
			kept = append(kept, t.Qualified())
		}
	}
	if len(kept) == 0 {
		return []string{}, nil
	}
	file := filepath.Join(workDir, "preserve.pgc")
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := client.DumpCommand(ctx, old, args)
	cmd.Stdout = f
	stderr := &dump.TailBuffer{Max: 64 << 10}
	cmd.Stderr = stderr
	err = cmd.Run()
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("dump preserved tables: %v: %s", err, dump.Scrub(stderr.String(), old))
	}
	if err := runRestore(ctx, client, newCI, file, 1, "--clean", "--if-exists"); err != nil {
		return nil, fmt.Errorf("preserve_tables: %w", err)
	}
	return kept, nil
}

func retry(ctx context.Context, fn func() error) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = fn(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(200*(i+1)) * time.Millisecond):
		}
	}
	return err
}

func ident(s string) string { return pgx.Identifier{s}.Sanitize() }

func quoteLit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// shorten keeps database names within PostgreSQL's 63-byte limit.
func shorten(base, suffix string) string {
	if len(base)+len(suffix) > 63 {
		base = base[:63-len(suffix)]
	}
	return base + suffix
}
