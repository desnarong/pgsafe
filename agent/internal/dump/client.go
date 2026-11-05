package dump

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/redact"
)

const (
	ModeLocal  = "local"
	ModeDocker = "docker"

	// DockerHostAlias reaches the host from a container (Docker Desktop, and
	// Linux via --add-host=...:host-gateway).
	DockerHostAlias = "host.docker.internal"
	containerWork   = "/pgsafe-work"
)

// Client runs pg_dump / pg_restore of one major version, either from a local
// install or inside the official postgres:<major> image.
type Client struct {
	Mode    string
	Major   int
	Version string // e.g. "16.4"
	BinDir  string // local mode ("" = found on PATH)
	Image   string // docker mode
}

// DockerImage expands the "{major}" placeholder.
func DockerImage(tpl string, major int) string {
	if tpl == "" {
		tpl = "postgres:{major}"
	}
	return strings.ReplaceAll(tpl, "{major}", strconv.Itoa(major))
}

// Resolve finds a client whose major version equals major. mode is
// auto | local | docker. The major must match exactly: an archive written by a
// newer pg_dump may not be readable by the pg_restore of the source version.
func Resolve(ctx context.Context, mode string, major int, imageTpl string) (*Client, error) {
	var localErr error
	if mode == "auto" || mode == ModeLocal {
		c, err := resolveLocal(ctx, major)
		if err == nil {
			return c, nil
		}
		localErr = err
		if mode == ModeLocal {
			return nil, err
		}
	}
	c, err := resolveDocker(ctx, major, DockerImage(imageTpl, major))
	if err != nil {
		if localErr != nil {
			return nil, fmt.Errorf("no pg_dump %d found: %v; and docker fallback failed: %w", major, localErr, err)
		}
		return nil, err
	}
	return c, nil
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func localCandidates(major int) []string {
	m := strconv.Itoa(major)
	var dirs []string
	if d := os.Getenv("PGSAFE_PG_BIN_DIR"); d != "" {
		dirs = append(dirs, strings.ReplaceAll(d, "{major}", m))
	}
	dirs = append(dirs,
		"/usr/lib/postgresql/"+m+"/bin", // Debian/Ubuntu (PGDG)
		"/usr/pgsql-"+m+"/bin",          // RHEL (PGDG)
		"/opt/homebrew/opt/postgresql@"+m+"/bin",
		"/usr/local/opt/postgresql@"+m+"/bin",
		`C:\Program Files\PostgreSQL\`+m+`\bin`,
		"", // PATH
	)
	return dirs
}

func resolveLocal(ctx context.Context, major int) (*Client, error) {
	var tried []string
	for _, dir := range localCandidates(major) {
		bin := exe("pg_dump")
		if dir != "" {
			bin = filepath.Join(dir, bin)
			if _, err := os.Stat(bin); err != nil {
				continue
			}
		} else if p, err := exec.LookPath(bin); err == nil {
			bin = p
			dir = filepath.Dir(p)
		} else {
			continue
		}
		ver, err := toolVersion(ctx, exec.CommandContext(ctx, bin, "--version"))
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (%v)", bin, err))
			continue
		}
		if verMajor(ver) != major {
			tried = append(tried, fmt.Sprintf("%s is %s", bin, ver))
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, exe("pg_restore"))); err != nil {
			tried = append(tried, fmt.Sprintf("%s has no pg_restore", dir))
			continue
		}
		return &Client{Mode: ModeLocal, Major: major, Version: ver, BinDir: dir}, nil
	}
	if len(tried) == 0 {
		return nil, fmt.Errorf("pg_dump %d not installed (set PGSAFE_PG_BIN_DIR or install postgresql-client-%d)", major, major)
	}
	return nil, fmt.Errorf("pg_dump %d not found; tried %s", major, strings.Join(tried, "; "))
}

func resolveDocker(ctx context.Context, major int, image string) (*Client, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, errors.New("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute) // first use may pull the image
	defer cancel()
	ver, err := toolVersion(ctx, exec.CommandContext(ctx, "docker", "run", "--rm", image, "pg_dump", "--version"))
	if err != nil {
		return nil, fmt.Errorf("run pg_dump in %s: %w", image, err)
	}
	if verMajor(ver) != major {
		return nil, fmt.Errorf("image %s has pg_dump %s, need %d", image, ver, major)
	}
	return &Client{Mode: ModeDocker, Major: major, Version: ver, Image: image}, nil
}

var verRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+(?:\.\d+)?)`)

func toolVersion(ctx context.Context, cmd *exec.Cmd) (string, error) {
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(lastLines(errb.String(), 3)))
	}
	m := verRe.FindStringSubmatch(out.String())
	if m == nil {
		return "", fmt.Errorf("unexpected version output %q", strings.TrimSpace(out.String()))
	}
	return m[1], nil
}

func verMajor(v string) int {
	n, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return n
}

// DumpCommand returns a pg_dump command writing a custom-format archive to stdout.
func (c *Client) DumpCommand(ctx context.Context, ci *pg.ConnInfo, args []string) *exec.Cmd {
	base := append([]string{"--format=custom", "--no-password"}, args...)
	return c.command(ctx, ci, "pg_dump", base, "")
}

// RestoreCommand returns a pg_restore command reading the archive at dumpPath.
// extra arguments (e.g. --clean --if-exists) are appended.
func (c *Client) RestoreCommand(ctx context.Context, ci *pg.ConnInfo, dumpPath string, jobs int, extra ...string) *exec.Cmd {
	args := append([]string{"--no-password", "--no-owner", "--no-privileges", "--jobs=" + strconv.Itoa(max(jobs, 1))}, extra...)
	return c.command(ctx, ci, "pg_restore", args, dumpPath)
}

// command builds the exec.Cmd. The password is passed only via PGPASSWORD
// in the child's environment — never on the command line.
func (c *Client) command(ctx context.Context, ci *pg.ConnInfo, tool string, args []string, file string) *exec.Cmd {
	if c.Mode == ModeLocal {
		all := append([]string{"--dbname=" + ci.URL()}, args...)
		if file != "" {
			all = append(all, file)
		}
		cmd := exec.CommandContext(ctx, filepath.Join(c.BinDir, exe(tool)), all...)
		cmd.Env = append(os.Environ(), ci.Env()...)
		return cmd
	}

	target := ci
	if ci.IsLoopback() {
		target = ci.WithHost(DockerHostAlias)
	}
	name := "pgsafe-client-" + randHex(6)
	dargs := []string{"run", "--rm", "--name", name, "--label", "pgsafe.client=1",
		"--add-host=" + DockerHostAlias + ":host-gateway"}
	if ci.Password() != "" {
		dargs = append(dargs, "-e", "PGPASSWORD") // value comes from the docker CLI's env
	}
	if file != "" {
		dargs = append(dargs, "--mount", "type=bind,source="+filepath.Dir(file)+",target="+containerWork+",readonly")
	}
	dargs = append(dargs, c.Image, tool, "--dbname="+target.URL())
	dargs = append(dargs, args...)
	if file != "" {
		dargs = append(dargs, containerWork+"/"+filepath.Base(file))
	}
	cmd := exec.CommandContext(ctx, "docker", dargs...)
	cmd.Env = append(os.Environ(), ci.Env()...)
	// Killing the docker CLI does not stop the container; remove it too.
	cmd.Cancel = func() error {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 30 * time.Second
	return cmd
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RestoreErrors extracts "pg_restore: error:" lines (and the final summary).
func RestoreErrors(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "error:") || strings.HasPrefix(l, "pg_restore: warning: errors ignored on restore") {
			out = append(out, l)
		}
	}
	return out
}

// TailBuffer keeps the last Max bytes written (for bounded stderr capture).
type TailBuffer struct {
	Max int
	buf []byte
}

func (t *TailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if max := t.Max; max > 0 && len(t.buf) > max {
		t.buf = t.buf[len(t.buf)-max:]
	}
	return len(p), nil
}

func (t *TailBuffer) String() string { return string(t.buf) }

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Scrub removes credentials from tool output before it is shown or stored.
func Scrub(s string, ci *pg.ConnInfo) string {
	if ci == nil {
		return redact.String(s)
	}
	return redact.String(s, ci.Password())
}
