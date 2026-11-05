//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// pgsafeBin is built once by TestMain, together with every entry in extraBins
// (cloud_test.go registers the control plane there, so the agent-only tests
// build without server/).
var pgsafeBin string

type extraBin struct {
	path *string
	name string // binary name without extension
	pkg  string
}

var extraBins []extraBin

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pgsafe-e2e-bin-")
	if err != nil {
		panic(err)
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	pgsafeBin = filepath.Join(dir, "pgsafe"+exe)
	bins := append([]extraBin{{&pgsafeBin, "pgsafe", "github.com/desnarong/pgsafe/agent/cmd/pgsafe"}}, extraBins...)
	for _, b := range bins {
		*b.path = filepath.Join(dir, b.name+exe)
		build := exec.Command("go", "build", "-o", *b.path, b.pkg)
		build.Stdout, build.Stderr = os.Stdout, os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "build", b.pkg, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// workspace is a temp dir with a pgsafe.yaml, age keys and a private S3 prefix.
type workspace struct {
	t      *testing.T
	dir    string
	prefix string
	env    []string
}

type wsDB struct{ name, envVar, url string }

func sourceDBs() []wsDB {
	var out []wsDB
	for _, s := range sources {
		out = append(out, wsDB{name: fmt.Sprintf("shop%d", s.major), envVar: fmt.Sprintf("E2E_PG%d_URL", s.major), url: s.url})
	}
	return out
}

func s3Endpoint() string { return env("S3_ENDPOINT", "http://localhost:9000") }

// newWorkspace writes pgsafe.yaml. encryption is "age" or "none"; extra is
// appended verbatim (e.g. a verify: section).
func newWorkspace(t *testing.T, dbs []wsDB, encryption, extra string) *workspace {
	t.Helper()
	ws := &workspace{t: t, dir: t.TempDir(), prefix: "e2e-" + randHex(4) + "/"}
	ws.env = append(os.Environ(),
		"AWS_ACCESS_KEY_ID="+env("PGSAFE_DEV_MINIO_USER", "pgsafeminio"),
		"AWS_SECRET_ACCESS_KEY="+env("PGSAFE_DEV_MINIO_PASSWORD", "pgsafeminio"),
		"PGSAFE_AGE_IDENTITY_FILE="+filepath.Join(ws.dir, "keys", "backup.key"),
	)
	var b strings.Builder
	b.WriteString("version: 1\ndatabases:\n")
	for _, d := range dbs {
		fmt.Fprintf(&b, "  - name: %s\n    url: ${%s}\n    exclude_tables: [audit_raw_logs]\n    exclude_table_data: [sessions, cache_*]\n", d.name, d.envVar)
		ws.env = append(ws.env, d.envVar+"="+d.url)
	}
	fmt.Fprintf(&b, "storage:\n  type: s3\n  bucket: %s\n  prefix: %s\n  endpoint: %s\n", env("PGSAFE_DEV_BUCKET", "pgsafe-dev"), ws.prefix, s3Endpoint())
	if encryption == "age" {
		b.WriteString("encryption:\n  type: age\n  recipients_file: ./keys/backup.pub\n  identity_file: ${PGSAFE_AGE_IDENTITY_FILE}\n")
	} else {
		b.WriteString("encryption:\n  type: none\n")
	}
	b.WriteString(extra)
	if err := os.WriteFile(filepath.Join(ws.dir, "pgsafe.yaml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if encryption == "age" {
		ws.mustRun("init", "--generate-key", "--skip-checks")
	}
	t.Cleanup(func() { ws.cleanupPrefix() })
	return ws
}

type result struct {
	stdout, stderr string
	code           int
}

// run executes pgsafe in the workspace. Every invocation is checked for
// leaked database passwords in its output.
func (ws *workspace) run(args ...string) result {
	ws.t.Helper()
	cmd := exec.Command(pgsafeBin, args...)
	cmd.Dir = ws.dir
	cmd.Env = ws.env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := result{stdout: out.String(), stderr: errb.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		ws.t.Fatalf("run pgsafe %v: %v", args, err)
	}
	for _, s := range []string{r.stdout, r.stderr} {
		if strings.Contains(s, ":pgsafe@") || strings.Contains(s, "PGPASSWORD=") {
			ws.t.Fatalf("pgsafe %v leaked a credential:\n%s", args, s)
		}
	}
	return r
}

func (ws *workspace) mustRun(args ...string) result {
	ws.t.Helper()
	r := ws.run(args...)
	if r.code != 0 {
		ws.t.Fatalf("pgsafe %v: exit %d\nstdout:\n%s\nstderr:\n%s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

func (ws *workspace) runJSON(v any, wantCode int, args ...string) {
	ws.t.Helper()
	r := ws.run(append(args, "--json")...)
	if r.code != wantCode {
		ws.t.Fatalf("pgsafe %v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, r.code, wantCode, r.stdout, r.stderr)
	}
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		ws.t.Fatalf("pgsafe %v: bad JSON: %v\n%s", args, err, r.stdout)
	}
}

func minioClient(t *testing.T) *minio.Client {
	t.Helper()
	u, err := url.Parse(s3Endpoint())
	if err != nil {
		t.Fatal(err)
	}
	c, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(env("PGSAFE_DEV_MINIO_USER", "pgsafeminio"), env("PGSAFE_DEV_MINIO_PASSWORD", "pgsafeminio"), ""),
		Secure: u.Scheme == "https",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func bucket() string { return env("PGSAFE_DEV_BUCKET", "pgsafe-dev") }

func (ws *workspace) key(rel string) string { return ws.prefix + rel }

func (ws *workspace) getObject(rel string) []byte {
	ws.t.Helper()
	obj, err := minioClient(ws.t).GetObject(context.Background(), bucket(), ws.key(rel), minio.GetObjectOptions{})
	if err != nil {
		ws.t.Fatal(err)
	}
	defer obj.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(obj); err != nil {
		ws.t.Fatalf("get %s: %v", rel, err)
	}
	return buf.Bytes()
}

func (ws *workspace) putObject(rel string, data []byte) {
	ws.t.Helper()
	_, err := minioClient(ws.t).PutObject(context.Background(), bucket(), ws.key(rel), bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	if err != nil {
		ws.t.Fatal(err)
	}
}

func (ws *workspace) listKeys() []string {
	var keys []string
	for o := range minioClient(ws.t).ListObjects(context.Background(), bucket(), minio.ListObjectsOptions{Prefix: ws.prefix, Recursive: true}) {
		if o.Err != nil {
			ws.t.Fatal(o.Err)
		}
		keys = append(keys, strings.TrimPrefix(o.Key, ws.prefix))
	}
	return keys
}

func (ws *workspace) cleanupPrefix() {
	c := minioClient(ws.t)
	ch := make(chan minio.ObjectInfo)
	go func() {
		defer close(ch)
		for o := range c.ListObjects(context.Background(), bucket(), minio.ListObjectsOptions{Prefix: ws.prefix, Recursive: true}) {
			ch <- o
		}
	}()
	for e := range c.RemoveObjects(context.Background(), bucket(), ch, minio.RemoveObjectsOptions{}) {
		ws.t.Logf("cleanup %s: %v", e.ObjectName, e.Err)
	}
}

// assertNoLeftovers fails if any scratch or client container is still around.
func assertNoLeftovers(t *testing.T) {
	t.Helper()
	for _, label := range []string{"pgsafe.scratch=1", "pgsafe.client=1"} {
		out, err := exec.Command("docker", "ps", "-a", "-q", "--filter", "label="+label).Output()
		if err != nil {
			t.Fatalf("docker ps: %v", err)
		}
		if s := strings.TrimSpace(string(out)); s != "" {
			t.Errorf("containers with label %s left behind: %s", label, s)
		}
	}
}

// JSON shapes of the CLI output (only the fields the tests use).
type manifestJSON struct {
	BackupID   string `json:"backup_id"`
	Object     string `json:"object"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	Encryption string `json:"encryption"`
	Tables     []struct {
		Schema       string `json:"schema"`
		Name         string `json:"name"`
		Rows         int64  `json:"rows"`
		RowsExact    bool   `json:"rows_exact"`
		DataExcluded bool   `json:"data_excluded"`
	} `json:"tables"`
}

type backupJSON struct {
	Backups []struct {
		Database string        `json:"database"`
		Status   string        `json:"status"`
		BackupID string        `json:"backup_id"`
		Manifest *manifestJSON `json:"manifest"`
		Removed  []string      `json:"removed_by_retention"`
		Error    string        `json:"error"`
	} `json:"backups"`
}

type reportJSON struct {
	BackupID          string `json:"backup_id"`
	Status            string `json:"status"`
	TablesTotal       int    `json:"tables_total"`
	TablesOK          int    `json:"tables_ok"`
	RestoreDurationMS int64  `json:"restore_duration_ms"`
	Checks            []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"checks"`
}

type verifyJSON struct {
	Verifications []struct {
		Database string      `json:"database"`
		Status   string      `json:"status"`
		Report   *reportJSON `json:"report"`
		Error    string      `json:"error"`
	} `json:"verifications"`
}

func (r *reportJSON) check(name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "absent"
}
