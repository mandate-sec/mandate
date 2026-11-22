package config

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseAddressAndCredentialRoundTrip(t *testing.T) {
	for _, tc := range []struct{ input, host string }{
		{"::1", "::1"},
		{"[::1]", "::1"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		{"db.example", "db.example"},
		{"", "127.0.0.1"},
	} {
		cfg := Database{Host: tc.input, User: "local@review", Password: "test:/@?#%", DBName: "review #1"}
		u, err := url.Parse(cfg.buildDSN())
		if err != nil {
			t.Fatalf("could not parse generated URL for host %q", tc.input)
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil || host != tc.host || port != "5432" {
			t.Fatalf("host %q produced address %q", tc.input, u.Host)
		}
		password, ok := u.User.Password()
		if !ok || password != cfg.Password || u.User.Username() != cfg.User || u.Path != "/"+cfg.DBName {
			t.Fatalf("connection fields changed for host %q", tc.input)
		}
	}
}

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("ARTEX_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("ARTEX_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}
