package evidence

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func commitBlob(staged, final string) error {
	from, err := windowsMovePath(staged)
	if err != nil {
		return err
	}
	to, err := windowsMovePath(final)
	if err != nil {
		return err
	}
	// The file itself is already flushed. A write-through move avoids
	// syncing a directory handle, which Windows does not support here.
	if err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "move", Old: staged, New: final, Err: err}
	}
	return nil
}

func windowsMovePath(path string) (*uint16, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Use extended-length paths like os.Rename does for long workspaces.
	switch {
	case strings.HasPrefix(path, `\\?\`), strings.HasPrefix(path, `\\.\`):
	case strings.HasPrefix(path, `\\`):
		path = `\\?\UNC\` + path[2:]
	default:
		path = `\\?\` + path
	}
	return windows.UTF16PtrFromString(path)
}
