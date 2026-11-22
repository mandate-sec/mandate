package traffic

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateCaptureDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "traffic")
	if err := prepareCaptureDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := prepareCaptureDirectory(dir); err != nil {
		t.Fatalf("could not reopen capture directory: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatal("new capture directory is not private", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareCaptureDirectory(dir); err == nil {
		t.Fatal("accepted a group-readable legacy directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := prepareCaptureDirectory(dir); err != nil {
		t.Fatalf("rejected repaired permissions: %v", err)
	}
	link := filepath.Join(filepath.Dir(dir), "alias")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareCaptureDirectory(link); err == nil {
		t.Fatal("accepted symlink as capture directory")
	}
}
