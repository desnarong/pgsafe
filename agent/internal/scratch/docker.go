package scratch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/pg"
)

const (
	scratchUser = "pgsafe"
	scratchDB   = "pgsafe_verify"
	work        = "/pgsafe-work"
)

// Docker runs a throwaway postgres:<major> container per verify.
type Docker struct {
	ImageTemplate   string // "postgres:{major}"
	TmpfsBelowBytes int64
	ReadyTimeout    time.Duration
}

func (d *Docker) Name() string { return "docker" }

func (d *Docker) Start(ctx context.Context, o StartOptions) (Instance, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, errors.New("verify.runtime docker needs the docker CLI (or set verify.runtime: server)")
	}
	image := dump.DockerImage(d.ImageTemplate, o.Major)
	name := "pgsafe-scratch-" + o.RunID
	password := randomPassword()

	args := []string{"run", "-d", "--rm", "--name", name,
		"--label", LabelScratch + "=1", "--label", LabelRun + "=" + o.RunID, "--label", LabelDB + "=" + o.Database,
		"-e", "POSTGRES_USER=" + scratchUser, "-e", "POSTGRES_DB=" + scratchDB,
		"-e", "POSTGRES_PASSWORD", // value from the docker CLI env, not argv
		"-p", "127.0.0.1::5432",
		"--mount", "type=bind,source=" + o.WorkDir + ",target=" + work + ",readonly",
	}
	// tmpfs lives in RAM: only for databases that will clearly fit.
	if !o.NoTmpfs && d.TmpfsBelowBytes > 0 && o.DumpBytes > 0 && o.DumpBytes*RestoredSizeFactor < d.TmpfsBelowBytes {
		// The data dir must itself be the tmpfs: images < 18 declare a volume
		// at /var/lib/postgresql/data, 18 at /var/lib/postgresql.
		dataDir := "/var/lib/postgresql/data"
		if o.Major >= 18 {
			dataDir = "/var/lib/postgresql"
		}
		args = append(args, "--tmpfs", fmt.Sprintf("%s:rw,uid=999,gid=999,size=%d", dataDir, d.TmpfsBelowBytes))
	}
	// Durability is irrelevant for a throwaway restore; trade it for speed.
	args = append(args, image, "-c", "fsync=off", "-c", "synchronous_commit=off",
		"-c", "full_page_writes=off", "-c", "max_wal_size=4GB")

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(cmd.Environ(), "POSTGRES_PASSWORD="+password)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	inst := &dockerInstance{name: name}
	if err := cmd.Run(); err != nil {
		// The container may exist even though `run` failed (e.g. port bind).
		dctx, cancel := DestroyContext(ctx)
		defer cancel()
		_ = inst.Destroy(dctx)
		return nil, fmt.Errorf("start scratch container (%s): %v: %s", image, err, strings.TrimSpace(errb.String()))
	}
	inst.id = strings.TrimSpace(out.String())

	fail := func(err error) (Instance, error) {
		dctx, cancel := DestroyContext(ctx)
		defer cancel()
		_ = inst.Destroy(dctx)
		return nil, err
	}

	port, err := hostPort(ctx, name)
	if err != nil {
		return fail(err)
	}
	ci, err := pg.ParseURL(fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		scratchUser, password, net.JoinHostPort("127.0.0.1", port), scratchDB))
	if err != nil {
		return fail(err)
	}
	inst.ci = ci

	timeout := d.ReadyTimeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	if err := waitReady(ctx, ci, name, timeout); err != nil {
		return fail(err)
	}
	return inst, nil
}

func hostPort(ctx context.Context, name string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").Output()
	if err != nil {
		return "", fmt.Errorf("docker port %s: %w", name, err)
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	_, port, err := net.SplitHostPort(line)
	if err != nil {
		return "", fmt.Errorf("parse docker port output %q: %w", line, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("parse docker port output %q", line)
	}
	return port, nil
}

// waitReady polls over TCP. The image's init-time server listens only on the
// unix socket, so a TCP connection succeeds only once the final server is up.
func waitReady(ctx context.Context, ci *pg.ConnInfo, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := pg.Connect(cctx, ci)
		cancel()
		if err == nil {
			conn.Close(context.Background())
			return nil
		}
		last = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		state, _ := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", name).Output()
		if strings.TrimSpace(string(state)) == "false" {
			logs, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "20", name).CombinedOutput()
			return fmt.Errorf("scratch container exited during startup: %s", strings.TrimSpace(string(logs)))
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("scratch postgres not ready after %s: %v", timeout, last)
}

type dockerInstance struct {
	name, id string
	ci       *pg.ConnInfo
}

func (i *dockerInstance) ConnInfo() *pg.ConnInfo { return i.ci }
func (i *dockerInstance) Describe() string       { return "container " + i.name }

// Restore runs the container's own pg_restore (same major as the server)
// over the local socket. It runs as root so it can read the bind-mounted dump
// regardless of host file ownership; the dump dir stays private on the host.
func (i *dockerInstance) Restore(ctx context.Context, file string, jobs int) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-u", "0", i.name,
		"pg_restore", "--username="+scratchUser, "--dbname="+scratchDB,
		"--no-owner", "--no-privileges", "--jobs="+strconv.Itoa(max(jobs, 1)),
		work+"/"+file)
	stderr := &dump.TailBuffer{Max: 256 << 10}
	cmd.Stderr = stderr
	err := cmd.Run()
	return dump.Scrub(stderr.String(), i.ci), err
}

// DumpCommand runs the container's own pg_dump over the local socket.
func (i *dockerInstance) DumpCommand(ctx context.Context, args []string) *exec.Cmd {
	all := append([]string{"exec", i.name, "pg_dump", "--username=" + scratchUser, "--dbname=" + scratchDB,
		"--format=custom", "--no-password"}, args...)
	return exec.CommandContext(ctx, "docker", all...)
}

func (i *dockerInstance) Destroy(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "docker", "rm", "-f", "-v", i.name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such container") {
		return fmt.Errorf("remove scratch container %s: %v: %s", i.name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
