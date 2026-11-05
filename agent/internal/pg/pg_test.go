package pg

import (
	"strings"
	"testing"
)

func TestParseURLSeparatesPassword(t *testing.T) {
	ci, err := ParseURL("postgres://app:s3cr3t@db.internal:5432/shop?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ci.URL(), "s3cr3t") {
		t.Fatalf("URL() leaks password: %s", ci.URL())
	}
	if ci.Password() != "s3cr3t" || ci.Database() != "shop" || ci.Host() != "db.internal" {
		t.Fatalf("unexpected: %s %q %q", ci.URL(), ci.Database(), ci.Host())
	}
	if env := ci.Env(); len(env) != 1 || env[0] != "PGPASSWORD=s3cr3t" {
		t.Fatalf("Env() = %v", env)
	}
	q, _ := ParseURL("postgres://app@db/shop?password=p%40ss&sslmode=disable")
	if q.Password() != "p@ss" || strings.Contains(q.URL(), "password") {
		t.Fatalf("query password not extracted: %s", q.URL())
	}
}

func TestParseURLRejectsOtherSchemes(t *testing.T) {
	if _, err := ParseURL("mysql://x@y/z"); err == nil {
		t.Fatal("expected error")
	}
	_, err := ParseURL("postgres://u:hunter2@[bad")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
}

func TestWithHostAndDatabase(t *testing.T) {
	ci, _ := ParseURL("postgres://u:p@localhost:5414/shop")
	if !ci.IsLoopback() {
		t.Fatal("localhost should be loopback")
	}
	d := ci.WithHost("host.docker.internal").WithDatabase("other")
	if d.URL() != "postgres://u@host.docker.internal:5414/other" || d.Password() != "p" {
		t.Fatalf("got %s", d.URL())
	}
	if ci.URL() != "postgres://u@localhost:5414/shop" {
		t.Fatal("original modified")
	}
}

func TestHashSchemaOrderIndependent(t *testing.T) {
	a := []TableSchema{
		{Qualified: "public.a", Columns: []string{"id int"}, Constraints: []string{"a_pkey PRIMARY KEY (id)", "a_chk CHECK"}, Indexes: []string{"i1", "i2"}},
		{Qualified: "public.b", Columns: []string{"id int", "x text"}},
	}
	b := []TableSchema{
		{Qualified: "public.b", Columns: []string{"id int", "x text"}},
		{Qualified: "public.a", Columns: []string{"id int"}, Constraints: []string{"a_chk CHECK", "a_pkey PRIMARY KEY (id)"}, Indexes: []string{"i2", "i1"}},
	}
	if HashSchema(a) != HashSchema(b) {
		t.Fatal("hash depends on table/constraint/index order")
	}
	c := []TableSchema{a[0], {Qualified: "public.b", Columns: []string{"x text", "id int"}}}
	if HashSchema(a) == HashSchema(c) {
		t.Fatal("column order must change the hash")
	}
}
