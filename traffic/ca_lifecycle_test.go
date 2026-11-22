package traffic

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureCAStorage(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	public := tr.CACertPath()
	t.Cleanup(func() { _ = tr.Close() })
	data, err := os.ReadFile(public)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("expected exactly one public certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		t.Fatal("invalid public CA certificate", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "_ca")); !os.IsNotExist(err) {
		t.Fatal("unexpected legacy CA directory", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(public); !os.IsNotExist(err) {
		t.Fatal("temporary public certificate remained", err)
	}
}

func TestLegacyCARequiresOwnerMigration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "_ca"), 0700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "_ca", "mitmproxy-ca.pem")
	if err := os.WriteFile(old, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyCA(dir); err == nil {
		t.Fatal("accepted exposed legacy key")
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "fixture" {
		t.Fatal("legacy file changed")
	}
}
