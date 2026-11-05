package runlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if runs, err := Read(dir, 0); err != nil || runs != nil {
		t.Fatalf("empty Read = %v, %v", runs, err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := Append(dir, Run{ID: id, Kind: "backup", Status: "passed"}); err != nil {
			t.Fatal(err)
		}
	}
	// a corrupt line must not break reading
	f, _ := os.OpenFile(filepath.Join(dir, fileName), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{not json\n")
	f.Close()

	runs, err := Read(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].ID != "c" || runs[1].ID != "b" {
		t.Fatalf("Read = %+v", runs)
	}
}
