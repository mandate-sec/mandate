//go:build unix

package server

import (
	"os"
	"path/filepath"
	"testing"
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
