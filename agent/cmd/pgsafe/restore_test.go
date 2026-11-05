package main

import (
	"context"
	"strings"
	"testing"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

func TestConfirm(t *testing.T) {
	never := func() string { t.Fatal("must not prompt"); return "" }
	if err := confirm(true, "app", "app", false, never); err != nil {
		t.Errorf("--yes --confirm-db match: %v", err)
	}
	if err := confirm(true, "other", "app", true, never); err == nil {
		t.Error("--confirm-db mismatch must fail")
	}
	if err := confirm(true, "", "app", false, never); err == nil {
		t.Error("--yes without --confirm-db must fail")
	}
	if err := confirm(false, "", "app", false, never); err == nil || !strings.Contains(err.Error(), "--confirm-db=app") {
		t.Errorf("non-interactive without --yes: %v", err)
	}
	if err := confirm(false, "", "app", true, func() string { return "app\n" }); err != nil {
		t.Errorf("typed name: %v", err)
	}
	if err := confirm(false, "", "app", true, func() string { return "ap\n" }); err == nil {
		t.Error("wrong typed name must fail")
	}
}

func TestEquivalentCommandsHaveNoPassword(t *testing.T) {
	cfg := &config.Config{Storage: config.Storage{Type: "s3", Bucket: "b", Prefix: "p", Endpoint: "http://minio:9000"},
		Encryption: config.Encryption{IdentityFile: "/keys/backup.key"}}
	store, err := storage.New(context.Background(), cfg.Storage)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := pg.ParseURL("postgres://admin:hunter22@db:5432/app_restored")
	m := &manifest.Manifest{BackupID: "bk_1", Database: "app", Object: "dump.pgc.age", Encryption: "age", SHA256: "abc"}
	cmds := strings.Join(equivalentCommands(cfg, store, m, target, 4), "\n")
	for _, want := range []string{"s3://b/p/backups/app/bk_1/dump.pgc.age", "--endpoint-url http://minio:9000", "expect abc",
		"age -d -i /keys/backup.key", "createdb", "'app_restored'", "pg_restore --no-owner --no-privileges --jobs=4"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("missing %q in:\n%s", want, cmds)
		}
	}
	if strings.Contains(cmds, "hunter22") {
		t.Fatalf("password in equivalent commands:\n%s", cmds)
	}
}
