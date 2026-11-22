package selfupdate

import (
	"errors"
	"os"
	"testing"
)

// The test executable lives in an isolated Go build directory. Only create a
// previously absent staging marker, and never stage executable content.
func TestDisabledUpdaterIgnoresLocalState(t *testing.T) {
	p, err := ResolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(p.Marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(p.Marker) })
	const marker = "{}"
	if _, err := file.WriteString(marker); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	action, state := Bootstrap()
	if action != Continue || state != (State{}) || HasBackup() {
		t.Fatal("disabled updater reported an active update")
	}
	Settle()
	if err := Rollback(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("rollback: got %v, want ErrDisabled", err)
	}
	if data, err := os.ReadFile(p.Marker); err != nil || string(data) != marker {
		t.Fatal("disabled updater changed on-disk state")
	}
}
