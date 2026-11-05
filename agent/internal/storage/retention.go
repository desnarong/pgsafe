package storage

import (
	"fmt"
	"sort"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/config"
)

// RetentionItem is a backup considered by the retention policy.
type RetentionItem struct {
	ID        string
	CreatedAt time.Time
}

// ApplyRetention decides which backups to keep with a grandfather-father-son
// policy: the newest backup of each of the last `daily` days, `weekly` ISO
// weeks and `monthly` months that have backups (UTC). Whatever the policy
// says, the newest backup and every backup taken less than 24h before it are
// kept, so an ad-hoc backup is never deleted moments after it was made.
func ApplyRetention(items []RetentionItem, r config.Retention) (keep, remove []RetentionItem) {
	sorted := append([]RetentionItem(nil), items...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
		}
		return sorted[i].ID > sorted[j].ID
	})
	if len(sorted) == 0 {
		return nil, nil
	}

	kept := map[string]bool{}
	grace := sorted[0].CreatedAt.Add(-24 * time.Hour)
	for _, it := range sorted {
		if it.CreatedAt.After(grace) {
			kept[it.ID] = true
		}
	}
	bucket := func(n int, key func(time.Time) string) {
		seen := map[string]bool{}
		for _, it := range sorted {
			if len(seen) >= n {
				return
			}
			k := key(it.CreatedAt.UTC())
			if !seen[k] {
				seen[k] = true
				kept[it.ID] = true // newest in its period, since sorted desc
			}
		}
	}
	bucket(r.Daily, func(t time.Time) string { return t.Format("2006-01-02") })
	bucket(r.Weekly, func(t time.Time) string { y, w := t.ISOWeek(); return fmt.Sprintf("%d-W%02d", y, w) })
	bucket(r.Monthly, func(t time.Time) string { return t.Format("2006-01") })

	for _, it := range sorted {
		if kept[it.ID] {
			keep = append(keep, it)
		} else {
			remove = append(remove, it)
		}
	}
	return keep, remove
}
