package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestConcurrentSessionKeyCreation(t *testing.T) {
	base, data := t.TempDir(), t.TempDir()
	legacy := bytes.Repeat([]byte("x"), 32)
	for _, dir := range []string{base, data} {
		if err := os.WriteFile(filepath.Join(dir, "jwt.key"), legacy, 0600); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		key []byte
		err error
	}
	results := make(chan result, 12)
	for range cap(results) {
		go func() {
			key, err := loadOrCreateJWTKey(base, data)
			results <- result{key, err}
		}()
	}
	var first []byte
	for range cap(results) {
		r := <-results
		if r.err != nil || len(r.key) != 32 || bytes.Equal(r.key, legacy) {
			t.Fatalf("unexpected session key result: %v", r.err)
		}
		if first != nil && !bytes.Equal(first, r.key) {
			t.Fatal("concurrent starts returned different keys")
		}
		first = r.key
	}
	reopened, err := loadOrCreateJWTKey(base, data)
	if err != nil || !bytes.Equal(first, reopened) {
		t.Fatalf("restart did not preserve key: %v", err)
	}
}

func TestSessionKeyRefusesWorkspaceAndCorruption(t *testing.T) {
	base, data := t.TempDir(), t.TempDir()
	if _, err := loadOrCreateJWTKey(data, data); err == nil {
		t.Fatal("accepted key directory inside workspace")
	}
	if _, err := loadOrCreateJWTKey(base, data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "keys", sessionKeyFile)
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateJWTKey(base, data); err == nil {
		t.Fatal("accepted damaged key")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "damaged" {
		t.Fatal("unexpected rewrite of damaged key")
	}
}

func TestSessionKeyChecksOpenedFileIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"expected", "different"} {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, 32), 0600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.Lstat(filepath.Join(dir, "expected"))
	if err != nil {
		t.Fatal(err)
	}
	different, err := os.Open(filepath.Join(dir, "different"))
	if err != nil {
		t.Fatal(err)
	}
	defer different.Close()
	if key, err := readSessionKey(different, expected); err == nil || key != nil {
		t.Fatal("accepted a different file of the expected size")
	}
}
