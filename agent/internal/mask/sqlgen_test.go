package mask

import (
	"strings"
	"testing"

	"github.com/desnarong/pgsafe/agent/internal/pg"
)

func strp(s string) *string { return &s }

func TestExpr(t *testing.T) {
	text := Col{Name: "Email", Type: "text"}
	tests := []struct {
		col  Col
		rule Rule
		want string
	}{
		{text, Rule{Strategy: "fake_email"}, `pgsafe_mask.fake_email("Email"::text)::text`},
		{Col{Name: "citizen_id", Type: "character(13)"}, Rule{Strategy: "fake_thai_id"}, `pgsafe_mask.fake_thai_id("citizen_id"::text)::character(13)`},
		{Col{Name: "full_name", Type: "text"}, Rule{Strategy: "fake_name_th"}, `pgsafe_mask.fake_name_th("full_name"::text, 'full')::text`},
		{Col{Name: "first_name", Type: "text"}, Rule{Strategy: "fake_name_th", Part: "first"}, `pgsafe_mask.fake_name_th("first_name"::text, 'first')::text`},
		{Col{Name: "card_last4", Type: "character(4)"}, Rule{Strategy: "static", Value: strp("0000")}, `CASE WHEN "card_last4" IS NULL THEN NULL ELSE '0000'::character(4) END`},
		{Col{Name: "x", Type: "text"}, Rule{Strategy: "static", Value: strp("it's")}, `CASE WHEN "x" IS NULL THEN NULL ELSE 'it''s'::text END`},
		{Col{Name: "birth_date", Type: "date"}, Rule{Strategy: "date_shift", MaxDays: 30}, `("birth_date" + pgsafe_mask.shift_days("id"::text, 30) * interval '1 day')::date`},
		{Col{Name: "total", Type: "numeric(12,2)"}, Rule{Strategy: "number_noise", Pct: 5}, `("total"::numeric * pgsafe_mask.noise_factor("id"::text, 5))::numeric(12,2)`},
		{Col{Name: "payer_ip", Type: "inet"}, Rule{Strategy: "fake_ip"}, `pgsafe_mask.fake_ip("payer_ip"::text)::inet`},
		{Col{Name: "p", Type: "jsonb"}, Rule{Strategy: "json_mask", Keys: map[string]string{"email": "fake_email"}}, `pgsafe_mask.json_mask("p", '{"email":"fake_email"}'::jsonb)`},
		{Col{Name: "p", Type: "json"}, Rule{Strategy: "json_mask", Keys: map[string]string{"email": "fake_email"}}, `pgsafe_mask.json_mask("p"::jsonb, '{"email":"fake_email"}'::jsonb)::json`},
		{Col{Name: "n", Type: "text"}, Rule{Strategy: "null"}, `NULL::text`},
		{Col{Name: "e", Type: "text"}, Rule{Strategy: "sql", Expr: "left(e, 2) || '***'"}, `(left(e, 2) || '***')::text`},
	}
	for _, tt := range tests {
		got, err := Expr(tt.col, tt.rule, `"id"::text`)
		if err != nil {
			t.Errorf("%s/%s: %v", tt.col.Name, tt.rule.Strategy, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s/%s:\n got %s\nwant %s", tt.col.Name, tt.rule.Strategy, got, tt.want)
		}
	}
	bad := []struct {
		col  Col
		rule Rule
	}{
		{Col{Name: "n", Type: "text", NotNull: true}, Rule{Strategy: "null"}},
		{Col{Name: "d", Type: "text"}, Rule{Strategy: "date_shift"}},
		{Col{Name: "j", Type: "text"}, Rule{Strategy: "json_mask", Keys: map[string]string{"a": "hash"}}},
		{Col{Name: "a", Type: "text[]"}, Rule{Strategy: "fake_email"}},
	}
	for _, b := range bad {
		if _, err := Expr(b.col, b.rule, ""); err == nil {
			t.Errorf("%s/%s should fail", b.col.Type, b.rule.Strategy)
		}
	}
}

func TestRowKeyFallsBackToValue(t *testing.T) {
	got, _ := Expr(Col{Name: "d", Type: "date"}, Rule{Strategy: "date_shift", MaxDays: 10}, "")
	if !strings.Contains(got, `shift_days("d"::text, 10)`) {
		t.Fatalf("got %s", got)
	}
	if k := rowKeyExpr([]string{"a", "b"}); k != `"a"::text || '|' || "b"::text` {
		t.Fatalf("rowKeyExpr = %s", k)
	}
}

func TestStatements(t *testing.T) {
	p := &TablePlan{
		Table: pg.Table{Schema: "public", Name: "customers", OID: 42},
		Cols:  []Col{{Name: "id", Type: "integer"}, {Name: "email", Type: "text"}, {Name: "gen", Type: "text", Generated: true}},
		PK:    []string{"id"},
		Rules: map[string]Rule{"email": {Strategy: "fake_email"}},
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	p.Path = PathUpdate
	if got := p.Statements(); len(got) != 1 || got[0] != `UPDATE "public"."customers" SET "email" = pgsafe_mask.fake_email("email"::text)::text` {
		t.Fatalf("update: %v", got)
	}
	p.Path = PathCTAS
	got := p.Statements()
	want := []string{
		`CREATE UNLOGGED TABLE "pgsafe_mask"."ctas_42" AS SELECT "id" AS "id", pgsafe_mask.fake_email("email"::text)::text AS "email" FROM "public"."customers"`,
		`TRUNCATE "public"."customers"`,
		`INSERT INTO "public"."customers" ("id", "email") OVERRIDING SYSTEM VALUE SELECT "id", "email" FROM "pgsafe_mask"."ctas_42"`,
		`DROP TABLE "pgsafe_mask"."ctas_42"`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ctas:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	p.Rules["gen"] = Rule{Strategy: "hash"}
	if err := p.Prepare(); err == nil {
		t.Fatal("masking a generated column should fail")
	}
}

func TestPrefixed(t *testing.T) {
	got := prefixed(rowKeyExpr([]string{"id", `we"ird`}), "x.")
	if got != `x."id"::text || '|' || x."we""ird"::text` {
		t.Fatalf("prefixed = %s", got)
	}
}
