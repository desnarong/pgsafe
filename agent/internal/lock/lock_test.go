package lock

import (
	"errors"
	"testing"
)

func TestDatabaseLock(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Database(dir, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Database(dir, "shop"); !errors.Is(err, ErrHeld) {
		t.Fatalf("second lock: %v, want ErrHeld", err)
	}
	if DatabaseFree(dir, "shop") {
		t.Fatal("DatabaseFree while held")
	}
	other, err := Database(dir, "other")
	if err != nil {
		t.Fatalf("different database must not conflict: %v", err)
	}
	other()
	unlock()
	if !DatabaseFree(dir, "shop") {
		t.Fatal("lock not released")
	}
}

func TestDaemonLock(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Daemon(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := Daemon(dir); !errors.Is(err, ErrHeld) {
		t.Fatalf("second daemon: %v", err)
	}
	dbUnlock, err := Database(dir, "daemon")
	if err != nil {
		t.Fatalf("db named 'daemon' must not collide with the daemon lock: %v", err)
	}
	dbUnlock()
}
