// Package ids generates sortable identifiers (ULID) with a type prefix.
package ids

import (
	"crypto/rand"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

func newID(prefix string, t time.Time) string {
	return prefix + ulid.MustNew(ulid.Timestamp(t), rand.Reader).String()
}

// Backup returns a backup ID like "bk_01JC…".
func Backup(t time.Time) string { return newID("bk_", t) }

// Run returns a run ID like "run_01JC…".
func Run(t time.Time) string { return newID("run_", t) }

// Short returns a lowercase suffix safe for database/container names.
func Short(id string) string {
	_, rest, ok := strings.Cut(id, "_")
	if !ok {
		rest = id
	}
	return strings.ToLower(rest)
}

// Masked returns a masked dump ID like "mk_01JC…".
func Masked(t time.Time) string { return newID("mk_", t) }
