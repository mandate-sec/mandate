//go:build !windows

package evidence

import (
	"os"
	"path/filepath"
)

func commitBlob(staged, final string) error {
	if err := os.Rename(staged, final); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(final))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
