package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	_ "modernc.org/sqlite"
)

func TestSetupToken(t *testing.T) {
	token := strings.Repeat("a", 64)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	for _, tc := range []struct {
		name, token, digest string
		want                bool
	}{
		{"valid", token, digest, true},
		{"unconfigured", token, "", false},
		{"missing token", "", digest, false},
		{"wrong token", strings.Repeat("b", 64), digest, false},
		{"malformed digest", token, strings.Repeat("x", 64), false},
		{"digest used as token", digest, digest, false},
	} {
		if got := validSetupToken(tc.token, tc.digest); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestFirstAdminSetupRequiresOwner(t *testing.T) {
	store, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetMaxOpenConns(1)
	if _, err := store.Exec("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: &db.DB{DB: store}}, jwtKey: []byte("fixture signing key")}
	handler := s.Handler()
	owner := strings.Repeat("a", 64)
	t.Setenv("MANDATE_SETUP_TOKEN_SHA256", fmt.Sprintf("%x", sha256.Sum256([]byte(owner))))
	setup := func(token string, want int) string {
		t.Helper()
		body := fmt.Sprintf(`{"password":"fixture password","setupToken":%q}`, token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/init", strings.NewReader(body)))
		var result struct{ Token string }
		if w.Code != want || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("setup returned status %d, expected %d with JSON", w.Code, want)
		}
		if want != http.StatusOK && result.Token != "" {
			t.Fatal("rejected setup issued a session")
		}
		return result.Token
	}
	for _, token := range []string{"", strings.Repeat("b", 64)} {
		setup(token, http.StatusForbidden)
		hash, _, err := s.m.pg.AdminCredentials()
		if err != nil || hash != "" {
			t.Fatal("rejected setup did not leave credentials empty", err)
		}
	}
	session := setup(owner, http.StatusOK)
	hash, generation, err := s.m.pg.AdminCredentials()
	if err != nil || hash == "" || !verifyJWT(session, sessionSigningKey(s.jwtKey, generation)) {
		t.Fatal("owner setup did not persist credentials and issue a valid session", err)
	}
	setup(owner, http.StatusForbidden)
	current, _, err := s.m.pg.AdminCredentials()
	if err != nil || current != hash {
		t.Fatal("repeated setup changed the password hash", err)
	}
}
