package stage

import (
	"strings"
	"testing"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

func ci(t *testing.T, s string) *pg.ConnInfo {
	c, err := pg.ParseURL(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSameDatabase(t *testing.T) {
	same := [][2]string{
		{"postgres://a:x@localhost:5416/shop", "postgres://b:y@127.0.0.1:5416/shop?sslmode=disable"},
		{"postgres://a@db.internal/shop", "postgres://a@db.internal:5432/shop"},
	}
	for _, p := range same {
		if !SameDatabase(ci(t, p[0]), ci(t, p[1])) {
			t.Errorf("%s vs %s should be the same database", p[0], p[1])
		}
	}
	diff := [][2]string{
		{"postgres://a@localhost:5416/shop", "postgres://a@localhost:5433/shop"},
		{"postgres://a@localhost:5416/shop", "postgres://a@localhost:5416/shop_staging"},
		{"postgres://a@db1/shop", "postgres://a@db2/shop"},
	}
	for _, p := range diff {
		if SameDatabase(ci(t, p[0]), ci(t, p[1])) {
			t.Errorf("%s vs %s should differ", p[0], p[1])
		}
	}
}

func TestShorten(t *testing.T) {
	long := strings.Repeat("a", 60)
	if got := shorten(long, "_pgsafe_new_abc"); len(got) != 63 || !strings.HasSuffix(got, "_pgsafe_new_abc") {
		t.Fatalf("shorten = %q (%d)", got, len(got))
	}
	if got := shorten("shop", "_x"); got != "shop_x" {
		t.Fatal(got)
	}
}
