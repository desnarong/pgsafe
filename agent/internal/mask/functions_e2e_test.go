//go:build e2e

package mask

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/scan"
)

// fnDB creates a throwaway database on the dev staging server with the
// masking functions installed.
func fnDB(t *testing.T, salt string) *pgx.Conn {
	t.Helper()
	admin := os.Getenv("STAGING_DATABASE_URL")
	if admin == "" {
		admin = "postgres://pgsafe:pgsafe@localhost:5433/shop_staging?sslmode=disable"
	}
	ci, err := pg.ParseURL(admin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ac, err := pg.Connect(ctx, ci)
	if err != nil {
		t.Skipf("dev env not running: %v", err)
	}
	b := make([]byte, 4)
	rand.Read(b)
	name := "pgsafe_fn_" + hex.EncodeToString(b)
	if _, err := ac.Exec(ctx, "create database "+name); err != nil {
		t.Fatal(err)
	}
	conn, err := pg.Connect(ctx, ci.WithDatabase(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close(ctx)
		ac.Exec(ctx, "drop database if exists "+name+" with (force)")
		ac.Close(ctx)
	})
	if err := Install(ctx, conn, salt); err != nil {
		t.Fatal(err)
	}
	return conn
}

func one[T any](t *testing.T, conn *pgx.Conn, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return v
}

const saltA = "salt-A-0123456789abcdef"

func TestSQLDeterministicAndSalted(t *testing.T) {
	conn := fnDB(t, saltA)
	exprs := []string{
		"pgsafe_mask.hash($1)", "pgsafe_mask.fake_email($1)", "pgsafe_mask.fake_phone_th('0812345678' || $1)",
		"pgsafe_mask.fake_thai_id('1101700207030' || $1)", "pgsafe_mask.fake_name_th($1, 'full')",
		"pgsafe_mask.fake_address_th($1)", "pgsafe_mask.fake_ip('203.150.1.2' || $1)",
	}
	first := map[string]string{}
	for _, e := range exprs {
		a := one[string](t, conn, "select "+e, "")
		b := one[string](t, conn, "select "+e, "")
		if a != b {
			t.Errorf("%s not deterministic: %q vs %q", e, a, b)
		}
		first[e] = a
	}
	// Different salt → different output.
	if err := Install(context.Background(), conn, "salt-B-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	for _, e := range exprs {
		if got := one[string](t, conn, "select "+e, ""); got == first[e] {
			t.Errorf("%s ignores the salt: %q", e, got)
		}
	}
	// Email normalisation keeps joins working across case/whitespace.
	if one[string](t, conn, "select pgsafe_mask.fake_email('A.B@Gmail.com ')") != one[string](t, conn, "select pgsafe_mask.fake_email('a.b@gmail.com')") {
		t.Error("fake_email should ignore case and surrounding spaces")
	}
}

// FPE strategies are bijections: 100k distinct inputs → 100k distinct valid outputs.
func TestSQLFormatPreservingIsUniqueAndValid(t *testing.T) {
	conn := fnDB(t, saltA)
	const n = 100000
	cases := []struct{ name, input, out, valid string }{
		{"thai_id",
			"(select p || pgsafe_mask.thai_id_check(p) from (select '1' || lpad(i::text, 11, '0') as p) x)",
			"pgsafe_mask.fake_thai_id(v)",
			"length(o) = 13 and right(o, 1) = pgsafe_mask.thai_id_check(left(o, 12))"},
		{"phone", "'08' || lpad(i::text, 8, '0')", "pgsafe_mask.fake_phone_th(v)", "o ~ '^08[0-9]{8}$'"},
		{"phone_intl", "'+668' || lpad(i::text, 8, '0')", "pgsafe_mask.fake_phone_th(v)", "o ~ '^\\+668[0-9]{8}$'"},
		{"card",
			"(select p || pgsafe_mask.luhn_check(p) from (select '4' || lpad(i::text, 14, '0') as p) x)",
			"pgsafe_mask.fake_card(v)",
			"length(o) = 16 and left(o, 1) = '4' and right(o, 1) = pgsafe_mask.luhn_check(left(o, 15))"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sql := `with s as (select ` + c.input + ` as v from generate_series(1, $1) i),
			             m as (select v, ` + c.out + ` as o from s)
			        select count(distinct o), count(*) filter (where not (` + c.valid + `)), count(*) filter (where o = v) from m`
			var distinct, invalid, unchanged int
			if err := conn.QueryRow(context.Background(), sql, n).Scan(&distinct, &invalid, &unchanged); err != nil {
				t.Fatal(err)
			}
			if distinct != n || invalid != 0 || unchanged > 1 {
				t.Fatalf("distinct=%d/%d invalid=%d unchanged=%d", distinct, n, invalid, unchanged)
			}
		})
	}
	// The outputs pass the scanner's own validators too.
	id := one[string](t, conn, "select pgsafe_mask.fake_thai_id('1-1017-00207-03-0')")
	if !scan.IsThaiID(id) || len(id) != 17 {
		t.Errorf("formatted thai id = %q", id)
	}
	if card := one[string](t, conn, "select pgsafe_mask.fake_card('4111111111111111')"); !scan.IsCard(card) {
		t.Errorf("fake card %q fails Luhn", card)
	}
}

func TestSQLOtherStrategies(t *testing.T) {
	conn := fnDB(t, saltA)
	if e := one[string](t, conn, "select pgsafe_mask.fake_email('somchai@gmail.com')"); !scan.IsEmail(e) || len(e) != len("user_0123456789abcdef@example.test") {
		t.Errorf("fake_email = %q", e)
	}
	full := one[string](t, conn, "select pgsafe_mask.fake_name_th('x', 'full')")
	if !scan.IsNameTH(full) {
		t.Errorf("fake_name_th full = %q has no title", full)
	}
	for _, part := range []string{"first", "last"} {
		if v := one[string](t, conn, "select pgsafe_mask.fake_name_th('x', $1)", part); v == "" || v == full {
			t.Errorf("fake_name_th %s = %q", part, v)
		}
	}
	if v := one[string](t, conn, "select pgsafe_mask.fake_name_en('x', 'full')"); len(v) < 5 {
		t.Errorf("fake_name_en = %q", v)
	}
	if a := one[string](t, conn, "select pgsafe_mask.fake_address_th('x')"); !scan.IsAddressTH(a) {
		t.Errorf("fake_address_th = %q", a)
	}
	if ok := one[bool](t, conn, "select pgsafe_mask.fake_ip('203.150.1.2')::inet << '10.0.0.0/8'"); !ok {
		t.Error("fake_ip v4 not in 10/8")
	}
	if ok := one[bool](t, conn, "select pgsafe_mask.fake_ip('2001:db8::1')::inet << 'fd00::/8'"); !ok {
		t.Error("fake_ip v6 not in fd00::/8")
	}
	if bad := one[int64](t, conn, "select count(*) from generate_series(1, 2000) i where abs(pgsafe_mask.shift_days(i::text, 30)) > 30"); bad != 0 {
		t.Errorf("date shift out of range: %d", bad)
	}
	if bad := one[int64](t, conn, "select count(*) from generate_series(1, 2000) i where pgsafe_mask.noise_factor(i::text, 10) not between 0.9 and 1.1"); bad != 0 {
		t.Errorf("noise out of range: %d", bad)
	}
	red := one[string](t, conn, "select pgsafe_mask.redact('โทร 081-234-5678 หรือ a.b@gmail.com บัตร 1 1017 00207 03 0 สั่ง 3 ชิ้น')")
	if scan.ContainsPII(red) || red != "โทร [REDACTED] หรือ [REDACTED] บัตร [REDACTED] สั่ง 3 ชิ้น" {
		t.Errorf("redact = %q", red)
	}
	js := one[string](t, conn, `select pgsafe_mask.json_mask('{"email":"a@b.co","lang":"th","n":{"x":1}}', '{"email":"fake_email","missing":"hash"}')::text`)
	if js != `{"n": {"x": 1}, "lang": "th", "email": "user_`+js[len(`{"n": {"x": 1}, "lang": "th", "email": "user_`):len(js)-len(`@example.test"}`)]+`@example.test"}` {
		t.Errorf("json_mask = %s", js)
	}
	for _, fn := range []string{"fake_email", "fake_phone_th", "fake_thai_id", "fake_card", "fake_address_th", "hash", "redact"} {
		if v := one[*string](t, conn, "select pgsafe_mask."+fn+"(null)"); v != nil {
			t.Errorf("%s(NULL) = %q, want NULL", fn, *v)
		}
	}
}
