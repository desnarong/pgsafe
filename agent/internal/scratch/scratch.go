package scratch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

// Labels put on every scratch container, so orphans can be found and removed
// (`docker ps -a --filter label=pgsafe.scratch=1`).
const (
	LabelScratch = "pgsafe.scratch"
	LabelRun     = "pgsafe.run"
	LabelDB      = "pgsafe.db" // configured database name, for orphan cleanup
	DBPrefix     = "pgsafe_verify_"
)

// StartOptions describe the scratch instance a verify run needs.
type StartOptions struct {
	RunID     string // used in container / database names
	Database  string // configured database name (labels / comments for cleanup)
	Major     int    // PostgreSQL major of the backup
	WorkDir   string // directory holding the decrypted dump (mounted read-only)
	DumpBytes int64  // size hint (docker runtime uses tmpfs for small dumps)
	NoTmpfs   bool   // never use tmpfs (masking writes a second copy of big tables)
}

// RestoredSizeFactor estimates restored database size from a compressed
// custom-format dump: data, indexes and TOAST are typically 3–10x larger.
const RestoredSizeFactor = 10

// Instance is a running scratch database.
type Instance interface {
	// ConnInfo connects to the scratch database.
	ConnInfo() *pg.ConnInfo
	// Restore runs pg_restore of WorkDir/<file>; it returns the captured
	// (credential-free) stderr and the exit error.
	Restore(ctx context.Context, file string, jobs int) (stderr string, err error)
	// DumpCommand returns a pg_dump --format=custom of the scratch database
	// writing to stdout (used to publish masked dumps).
	DumpCommand(ctx context.Context, args []string) *exec.Cmd
	// Destroy removes the scratch database / container. It must be called on
	// every path, including failures and cancellation.
	Destroy(ctx context.Context) error
	// Describe names the instance for logs.
	Describe() string
}

// Runtime provisions scratch instances.
type Runtime interface {
	Name() string
	Start(ctx context.Context, o StartOptions) (Instance, error)
}

// DestroyContext returns a context for cleanup that survives cancellation of
// the parent (e.g. Ctrl-C) but still has a deadline.
func DestroyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 2*time.Minute)
}

func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
