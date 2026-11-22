//go:build unix

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionKeyRejectsUnsafeUnixPermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  bool
		mode os.FileMode
	}{
		{"group readable key", false, 0640},
		{"world readable key", false, 0604},
		{"group writable directory", true, 0720},
		{"world writable directory", true, 0702},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, data := t.TempDir(), t.TempDir()
			if _, err := loadOrCreateJWTKey(base, data); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "keys")
			if !tc.dir {
				path = filepath.Join(path, sessionKeyFile)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			if key, err := loadOrCreateJWTKey(base, data); err == nil || key != nil {
				t.Fatal("loaded a key with unsafe permissions")
			}
		})
	}
}

func TestSessionKeyOpenRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "key")
	if err := os.WriteFile(target, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openSessionKey(link, expected); err == nil {
		t.Fatal("session key open followed a symlink")
	}
}

func TestSessionKeyOpenRejectsReplacedFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.key")
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("mkfifo", path).Run(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := openSessionKey(path, expected)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a replacement FIFO as a signing key")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening a replacement FIFO waited for a writer")
	}
}
