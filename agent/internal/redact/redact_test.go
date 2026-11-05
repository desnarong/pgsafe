package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct{ in, mustNot string }{
		{"connect postgres://app:s3cr3t@db:5432/x failed", "s3cr3t"},
		{"host=db user=app password=s3cr3t dbname=x", "s3cr3t"},
		{"host=db password='s3 cr3t' dbname=x", "s3 cr3t"},
		{"postgres://db/x?sslmode=disable&password=s3cr3t", "s3cr3t"},
	}
	for _, tt := range tests {
		out := String(tt.in)
		if strings.Contains(out, tt.mustNot) {
			t.Errorf("String(%q) = %q still contains secret", tt.in, out)
		}
	}
}

func TestStringExtraSecrets(t *testing.T) {
	out := String("pg_dump: error: auth failed for hunter22", "hunter22")
	if strings.Contains(out, "hunter22") {
		t.Fatalf("extra secret leaked: %q", out)
	}
}

func TestURL(t *testing.T) {
	got := URL("postgres://app:s3cr3t@db:5432/x?sslmode=require")
	if strings.Contains(got, "s3cr3t") || !strings.Contains(got, "app:") || !strings.Contains(got, "sslmode=require") {
		t.Fatalf("URL() = %q", got)
	}
	if got := URL("postgres://db/x"); got != "postgres://db/x" {
		t.Fatalf("URL without password changed: %q", got)
	}
}
