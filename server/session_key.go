package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const sessionKeyFile = "session-v2.key"

// Legacy jwt.key files may have been visible through the workspace browser.
// Use a fresh key for this format and never import legacy bytes.
func loadOrCreateJWTKey(baseDir, dataDir string) ([]byte, error) {
	workspace, err := os.Stat(dataDir)
	if err != nil {
		return nil, err
	}
	keyDir := filepath.Join(baseDir, "keys")
	if err := os.Mkdir(keyDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(keyDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || !sessionKeyOwned(info) || (runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) {
		return nil, errors.New("session key directory must be a directory writable only by its owner")
	}
	absolute, err := filepath.Abs(keyDir)
	if err != nil {
		return nil, err
	}
	keyDir, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	for dir := keyDir; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, err
		}
		if os.SameFile(info, workspace) {
			return nil, errors.New("session key directory must be outside the browsable workspace")
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	path := filepath.Join(keyDir, sessionKeyFile)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := createSessionKey(keyDir, path); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !sessionKeyOwned(info) || info.Size() != 32 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("invalid session key file type, length or permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key := make([]byte, 32)
	_, err = io.ReadFull(f, key)
	return key, err
}

func createSessionKey(dir, path string) error {
	f, err := os.CreateTemp(dir, ".session-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	key := make([]byte, 32)
	rand.Read(key)
	if _, err := f.Write(key); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Atomically publish a complete key. Concurrent starters use the winner.
	if err := os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("publish session key: %w", err)
	}
	return nil
}
