// Package pg handles connections, version detection, exported snapshots and
// schema reads (design doc §3.3).
package pg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/desnarong/pgsafe/agent/internal/redact"
)

// ConnInfo is a parsed postgres:// URL with the password held separately, so
// the URL can be passed on a command line (pg_dump --dbname) while the
// password only ever travels through the PGPASSWORD environment variable.
type ConnInfo struct {
	u        *url.URL // never contains a password
	password string
}

// ParseURL accepts postgres:// or postgresql:// URLs.
func ParseURL(raw string) (*ConnInfo, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid database url %s: %w", redact.URL(raw), errors.Unwrap(err))
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("database url must start with postgres:// (got %q)", u.Scheme+"://")
	}
	ci := &ConnInfo{u: u}
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			ci.password = p
			u.User = url.User(u.User.Username())
		}
	}
	if q := u.Query(); q.Has("password") {
		ci.password = q.Get("password")
		q.Del("password")
		u.RawQuery = q.Encode()
	}
	return ci, nil
}

// URL returns the connection URL without the password (safe for argv/logs).
func (c *ConnInfo) URL() string { return c.u.String() }

// Password returns the password (empty if none). Never log it.
func (c *ConnInfo) Password() string { return c.password }

// Database returns the database name in the URL path.
func (c *ConnInfo) Database() string { return strings.TrimPrefix(c.u.Path, "/") }

// Port returns the port in the URL ("" if absent).
func (c *ConnInfo) Port() string { return c.u.Port() }

// Host returns the host name without port.
func (c *ConnInfo) Host() string { return c.u.Hostname() }

// Env returns the environment entries a libpq client needs besides the URL.
func (c *ConnInfo) Env() []string {
	if c.password == "" {
		return nil
	}
	return []string{"PGPASSWORD=" + c.password}
}

// WithDatabase returns a copy pointing at another database on the same server.
func (c *ConnInfo) WithDatabase(name string) *ConnInfo {
	u := *c.u
	u.Path = "/" + name
	return &ConnInfo{u: &u, password: c.password}
}

// WithHost returns a copy with the host replaced (port kept).
func (c *ConnInfo) WithHost(host string) *ConnInfo {
	u := *c.u
	if port := c.u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	return &ConnInfo{u: &u, password: c.password}
}

// IsLoopback reports whether the host is localhost / 127.0.0.1 / ::1.
func (c *ConnInfo) IsLoopback() bool {
	h := c.Host()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Connect opens a pgx connection. Errors are scrubbed of the password.
func Connect(ctx context.Context, c *ConnInfo) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(c.u.String())
	if err != nil {
		return nil, fmt.Errorf("parse database url: %s", redact.String(err.Error(), c.password))
	}
	cfg.Password = c.password
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	if _, ok := cfg.RuntimeParams["application_name"]; !ok {
		cfg.RuntimeParams["application_name"] = "pgsafe"
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %s", redact.URL(c.u.String()), redact.String(err.Error(), c.password))
	}
	return conn, nil
}

// Version is the server version.
type Version struct {
	Num    int    // server_version_num, e.g. 160004
	Major  int    // 16
	String string // "16.4"
}

func ServerVersion(ctx context.Context, q Querier) (Version, error) {
	var v Version
	var full string
	err := q.QueryRow(ctx, "select current_setting('server_version_num')::int, current_setting('server_version')").Scan(&v.Num, &full)
	if err != nil {
		return v, fmt.Errorf("read server version: %w", err)
	}
	v.Major = v.Num / 10000
	v.String = strings.Fields(full)[0] // drop distro suffix like "(Debian 16.4-1.pgdg120+2)"
	return v, nil
}

// Querier is satisfied by *pgx.Conn and pgx.Tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}
