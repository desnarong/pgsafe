package scratch

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/pg"
)

// Server creates a temporary database on an existing scratch server
// (verify.server_url). That server must never be production.
type Server struct {
	ConnInfo    *pg.ConnInfo
	PGClient    string // auto | local | docker, for pg_restore
	DockerImage string
}

func (s *Server) Name() string { return "server" }

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (s *Server) Start(ctx context.Context, o StartOptions) (Instance, error) {
	conn, err := pg.Connect(ctx, s.ConnInfo)
	if err != nil {
		return nil, fmt.Errorf("scratch server: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	ver, err := pg.ServerVersion(ctx, conn)
	if err != nil {
		return nil, err
	}
	if ver.Major < o.Major {
		return nil, fmt.Errorf("scratch server is PostgreSQL %d but the backup is from %d; it must be the same or newer", ver.Major, o.Major)
	}
	// pg_restore must read archives written by pg_dump o.Major; the server's
	// own major (>= o.Major) is guaranteed to.
	client, err := dump.Resolve(ctx, s.PGClient, ver.Major, s.DockerImage)
	if err != nil {
		return nil, err
	}
	name := DBPrefix + o.RunID
	if _, err := conn.Exec(ctx, "create database "+pgx.Identifier{name}.Sanitize()); err != nil {
		return nil, fmt.Errorf("create scratch database %s: %w", name, err)
	}
	// Owner tag so an interrupted run's database can be found and dropped later.
	if _, err := conn.Exec(ctx, "comment on database "+pgx.Identifier{name}.Sanitize()+" is "+quote("pgsafe db="+o.Database)); err != nil {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "drop database if exists "+pgx.Identifier{name}.Sanitize())
		return nil, fmt.Errorf("tag scratch database %s: %w", name, err)
	}
	return &serverInstance{admin: s.ConnInfo, ci: s.ConnInfo.WithDatabase(name), name: name, client: client, workDir: o.WorkDir}, nil
}

type serverInstance struct {
	admin, ci *pg.ConnInfo
	name      string
	client    *dump.Client
	workDir   string
}

func (i *serverInstance) ConnInfo() *pg.ConnInfo { return i.ci }
func (i *serverInstance) Describe() string       { return "database " + i.name }

func (i *serverInstance) Restore(ctx context.Context, file string, jobs int) (string, error) {
	cmd := i.client.RestoreCommand(ctx, i.ci, filepath.Join(i.workDir, file), jobs)
	stderr := &dump.TailBuffer{Max: 256 << 10}
	cmd.Stderr = stderr
	err := cmd.Run()
	return dump.Scrub(stderr.String(), i.ci), err
}

func (i *serverInstance) DumpCommand(ctx context.Context, args []string) *exec.Cmd {
	return i.client.DumpCommand(ctx, i.ci, args)
}

func (i *serverInstance) Destroy(ctx context.Context) error {
	conn, err := pg.Connect(ctx, i.admin)
	if err != nil {
		return fmt.Errorf("drop scratch database %s: %w", i.name, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, "drop database if exists "+pgx.Identifier{i.name}.Sanitize()+" with (force)"); err != nil {
		return fmt.Errorf("drop scratch database %s: %w", i.name, err)
	}
	return nil
}
