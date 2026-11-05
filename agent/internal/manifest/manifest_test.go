package manifest

import (
	"reflect"
	"testing"
	"time"
)

func TestRoundtrip(t *testing.T) {
	m := &Manifest{
		BackupID: "bk_01J", Database: "app-prod", CreatedAt: time.Date(2026, 11, 5, 2, 0, 3, 0, time.UTC),
		PGServerVersion: "16.4", PGServerMajor: 16, PGDumpVersion: "16.4", Format: FormatCustom,
		Encryption: "age", Object: "dump.pgc.age", SizeBytes: 10, SHA256: "abc", SchemaHash: "def",
		Tables: []Table{{Schema: "public", Name: "orders", Rows: 3, RowsExact: true}},
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("roundtrip mismatch:\n%+v\n%+v", got, m)
	}
	if _, err := Parse([]byte(`{"backup_id":"x"}`)); err == nil {
		t.Fatal("incomplete manifest should fail")
	}
}
