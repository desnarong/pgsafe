// Package lock provides the file locks that keep pgsafe runs from overlapping:
// one daemon per state dir, and one run at a time per database. Locks are
// released by the OS if the process dies, so a stale lock never blocks.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/gofrs/flock"
)

// ErrHeld is wrapped when another process holds the lock.
var ErrHeld = errors.New("lock is held")

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

func path(stateDir, name string) string {
	return filepath.Join(stateDir, "locks", unsafeName.ReplaceAllString(name, "_")+".lock")
}

func acquire(p, what string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	fl := flock.New(p)
	ok, err := fl.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", p, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrHeld, what)
	}
	return func() { _ = fl.Unlock() }, nil
}

// Daemon takes the single-daemon lock for stateDir.
func Daemon(stateDir string) (func(), error) {
	return acquire(path(stateDir, "daemon"), "another pgsafe run (daemon) is already running with this state_dir")
}

// Database takes the per-database run lock.
func Database(stateDir, db string) (func(), error) {
	return acquire(path(stateDir, "db-"+db), "another pgsafe run is in progress for database "+db)
}

// DatabaseFree reports whether nobody holds db's lock (without keeping it).
func DatabaseFree(stateDir, db string) bool {
	unlock, err := Database(stateDir, db)
	if err != nil {
		return false
	}
	unlock()
	return true
}
