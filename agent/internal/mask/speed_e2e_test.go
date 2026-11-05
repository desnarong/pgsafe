//go:build e2e

package mask

import (
	"context"
	"testing"
	"time"
)

func TestSQLSpeed(t *testing.T) {
	conn := fnDB(t, saltA)
	for _, e := range []string{"pgsafe_mask.fake_thai_id('1' || lpad(i::text, 12, '0'))", "pgsafe_mask.fake_email(i::text)", "pgsafe_mask.fake_name_th(i::text,'full')", "pgsafe_mask.fake_address_th(i::text)", "pgsafe_mask.hash(i::text)"} {
		t0 := time.Now()
		if _, err := conn.Exec(context.Background(), "select count("+e+") from generate_series(1,100000) i"); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-60s %s / 100k", e, time.Since(t0).Round(time.Millisecond))
	}
}
