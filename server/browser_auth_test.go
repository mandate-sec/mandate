package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserCredentialTransport(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/health?token=url-secret", nil)
	if extractToken(r) != "" {
		t.Fatal("accepted a URL credential")
	}
	r.AddCookie(&http.Cookie{Name: "artex_token", Value: "cookie"})
	if extractToken(r) != "cookie" {
		t.Fatal("missing cookie credential")
	}
	r.Header.Set("Authorization", "Bearer header")
	if extractToken(r) != "header" {
		t.Fatal("explicit bearer credential should take precedence")
	}
}

func TestBrowserOriginPolicy(t *testing.T) {
	const ui = "http://localhost:3000"
	for _, tc := range []struct {
		config, origin, method string
		code                   int
		credentials            bool
	}{
		{"", ui, "GET", 200, false},
		{ui, ui, "GET", 200, true},
		{ui, "http://localhost:3001", "GET", 200, false},
		{"null", "null", "GET", 200, false},
		{ui, ui, "POST", 403, false},
		{"", "http://localhost:8787", "POST", 200, false},
	} {
		t.Setenv("MANDATE_STREAM_UI_ORIGIN", tc.config)
		r := httptest.NewRequest(tc.method, "http://localhost:8787/api/example", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		if w.Code != tc.code || (w.Header().Get("Access-Control-Allow-Credentials") == "true") != tc.credentials {
			t.Fatalf("%+v: got %d %v", tc, w.Code, w.Header())
		}
	}
}
