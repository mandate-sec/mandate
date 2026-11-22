//go:build linux

// Mandate — Scoped offensive security agent.
// Authorized penetration testing only. Use only with written authorization.
package config

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestConfigRejectsFIFOWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := loadFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a FIFO as configuration")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("config read blocked waiting for a FIFO writer")
	}
}
