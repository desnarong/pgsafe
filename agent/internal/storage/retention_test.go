package storage

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/config"
)

func ids(items []RetentionItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ID
	}
	sort.Strings(out)
	return out
}

// daily backups at 02:00 UTC for n days ending at end (inclusive).
func dailySeries(end time.Time, n int) []RetentionItem {
	var out []RetentionItem
	for i := 0; i < n; i++ {
		t := end.AddDate(0, 0, -i)
		out = append(out, RetentionItem{ID: t.Format("2006-01-02"), CreatedAt: t})
	}
	return out
}

func TestRetentionGFS(t *testing.T) {
	end := time.Date(2026, 11, 5, 2, 0, 0, 0, time.UTC) // Thursday
	items := dailySeries(end, 120)
	keep, remove := ApplyRetention(items, config.Retention{Daily: 7, Weekly: 4, Monthly: 6})

	want := map[string]bool{}
	for i := 0; i < 7; i++ { // last 7 days
		want[end.AddDate(0, 0, -i).Format("2006-01-02")] = true
	}
	// newest of the last 4 ISO weeks: this week's newest is today; previous weeks end on Sunday
	for _, d := range []string{"2026-11-01", "2026-10-25", "2026-10-18"} {
		want[d] = true
	}
	// newest of the last 6 months: Nov (today), Oct 31, Sep 30, Aug 31, Jul 31; series starts Jul 9
	for _, d := range []string{"2026-10-31", "2026-09-30", "2026-08-31", "2026-07-31"} {
		want[d] = true
	}
	got := ids(keep)
	if len(got) != len(want) {
		t.Fatalf("kept %d (%v), want %d", len(got), got, len(want))
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpectedly kept %s", id)
		}
	}
	if len(keep)+len(remove) != len(items) {
		t.Fatal("keep+remove must partition the input")
	}
}

func TestRetentionAlwaysKeepsNewest(t *testing.T) {
	items := dailySeries(time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), 3)
	keep, remove := ApplyRetention(items, config.Retention{})
	if got := ids(keep); len(got) != 1 || got[0] != "2026-01-10" {
		t.Fatalf("keep = %v", got)
	}
	if len(remove) != 2 {
		t.Fatalf("remove = %v", ids(remove))
	}
}

func TestRetentionKeepsLast24h(t *testing.T) {
	// Several ad-hoc backups within a day are all kept, even with daily: 1.
	day := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	var items []RetentionItem
	for h := 0; h < 5; h++ {
		items = append(items, RetentionItem{ID: fmt.Sprintf("h%d", h), CreatedAt: day.Add(time.Duration(h) * time.Hour)})
	}
	// Older ones on previous days: only the newest of each day survives daily: 2.
	items = append(items,
		RetentionItem{ID: "d1a", CreatedAt: day.Add(-30 * time.Hour)},
		RetentionItem{ID: "d1b", CreatedAt: day.Add(-26 * time.Hour)},
		RetentionItem{ID: "d2", CreatedAt: day.Add(-50 * time.Hour)},
	)
	keep, remove := ApplyRetention(items, config.Retention{Daily: 2})
	want := []string{"d1b", "h0", "h1", "h2", "h3", "h4"}
	if got := ids(keep); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("keep = %v, want %v", got, want)
	}
	if got := ids(remove); fmt.Sprint(got) != "[d1a d2]" {
		t.Fatalf("remove = %v", got)
	}
}

func TestRetentionEmpty(t *testing.T) {
	keep, remove := ApplyRetention(nil, config.Retention{Daily: 7})
	if keep != nil || remove != nil {
		t.Fatal("expected nil")
	}
}
