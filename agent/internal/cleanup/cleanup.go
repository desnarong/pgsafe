// Package cleanup removes what an interrupted pgsafe run left behind: scratch
// containers, scratch databases on a scratch server, half-built staging
// databases and old temp dirs. It only touches a database's leftovers while
// that database's run lock is free — i.e. no live run owns them.
package cleanup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/lock"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/scratch"
)

// Report lists what was removed.
type Report struct {
	Containers []string `json:"containers"`
	Databases  []string `json:"databases"`
	TempDirs   []string `json:"temp_dirs"`
	Skipped    []string `json:"skipped"` // databases whose lock is held by a live run
	Errors     []string `json:"errors"`
}

// Removed lists every removed item.
func (r *Report) Removed() []string {
	var out []string
	for _, c := range r.Containers {
		out = append(out, "container "+c)
	}
	for _, d := range r.Databases {
		out = append(out, "database "+d)
	}
	for _, d := range r.TempDirs {
		out = append(out, "temp dir "+d)
	}
	return out
}

func (r *Report) merge(o *Report) {
	r.Containers = append(r.Containers, o.Containers...)
	r.Databases = append(r.Databases, o.Databases...)
	r.TempDirs = append(r.TempDirs, o.TempDirs...)
	r.Errors = append(r.Errors, o.Errors...)
}

func newReport() *Report {
	return &Report{Containers: []string{}, Databases: []string{}, TempDirs: []string{}, Skipped: []string{}, Errors: []string{}}
}

// OwnerComment is the COMMENT ON DATABASE pgsafe writes on databases it
// creates temporarily, so cleanup knows which run owned them.
func OwnerComment(db string) string { return "pgsafe db=" + db }

// Database removes leftovers of db. The caller must hold db's run lock.
func Database(ctx context.Context, cfg *config.Config, db string) *Report {
	r := newReport()
	r.Containers = append(r.Containers, removeContainers(ctx, db, r)...)

	if cfg.Verify.Runtime == "server" && cfg.Verify.ServerURL != "" {
		if ci, err := pg.ParseURL(cfg.Verify.ServerURL); err == nil {
			dropOwned(ctx, ci, scratch.DBPrefix, db, r)
		}
	}
	for _, t := range cfg.Staging.Targets {
		if t.Type != "database" || t.URL == "" {
			continue
		}
		if ci, err := pg.ParseURL(t.URL); err == nil {
			dropOwned(ctx, ci.WithDatabase("postgres"), ci.Database()+"_pgsafe_new_", db, r)
		}
	}
	return r
}

// All cleans every configured database whose lock is free, and temp dirs
// older than a day.
func All(ctx context.Context, cfg *config.Config) *Report {
	r := newReport()
	stateDir := cfg.Resolve(cfg.StateDir)
	for _, d := range cfg.Databases {
		unlock, err := lock.Database(stateDir, d.Name)
		if err != nil {
			r.Skipped = append(r.Skipped, d.Name)
			continue
		}
		r.merge(Database(ctx, cfg, d.Name))
		unlock()
	}
	r.TempDirs = append(r.TempDirs, removeOldTempDirs(24*time.Hour, r)...)
	return r
}

func removeContainers(ctx context.Context, db string, r *Report) []string {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "docker", "ps", "-a", "--format", "{{.Names}}",
		"--filter", "label="+scratch.LabelScratch+"=1", "--filter", "label="+scratch.LabelDB+"="+db).Output()
	if err != nil {
		return nil // docker daemon not running: nothing we can clean
	}
	var removed []string
	for _, name := range strings.Fields(string(out)) {
		if msg, err := exec.CommandContext(cctx, "docker", "rm", "-f", "-v", name).CombinedOutput(); err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("remove container %s: %v: %s", name, err, strings.TrimSpace(string(msg))))
			continue
		}
		removed = append(removed, name)
	}
	return removed
}

// dropOwned drops databases named prefix* that carry db's owner comment.
func dropOwned(ctx context.Context, admin *pg.ConnInfo, prefix, db string, r *Report) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pg.Connect(cctx, admin)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return
	}
	defer conn.Close(context.WithoutCancel(ctx))
	rows, err := conn.Query(cctx, `
		select datname from pg_database d
		where starts_with(datname, $1) and shobj_description(d.oid, 'pg_database') = $2`, prefix, OwnerComment(db))
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return
	}
	for _, n := range names {
		if _, err := conn.Exec(cctx, "drop database if exists "+pgx.Identifier{n}.Sanitize()+" with (force)"); err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("drop %s: %v", n, err))
			continue
		}
		r.Databases = append(r.Databases, admin.Host()+"/"+n)
	}
}

// removeOldTempDirs removes pgsafe-* work dirs older than age.
func removeOldTempDirs(age time.Duration, r *Report) []string {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return nil
	}
	var removed []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "pgsafe-") {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < age {
			continue
		}
		p := filepath.Join(os.TempDir(), e.Name())
		if err := os.RemoveAll(p); err != nil {
			r.Errors = append(r.Errors, err.Error())
			continue
		}
		removed = append(removed, p)
	}
	return removed
}
