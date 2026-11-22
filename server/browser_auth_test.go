package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
		{ui, ui, "GET", 200, false},
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

func TestCredentialedOriginOnlyOnAuthenticatedStream(t *testing.T) {
	const ui = "http://localhost:3000"
	for _, tc := range []struct {
		config, origin   string
		session, allowed bool
	}{
		{ui, ui, true, true},
		{ui, ui, false, false},
		{ui, "http://localhost:3001", true, false},
		{"null", "null", true, false},
		{"", ui, true, false},
	} {
		t.Setenv("MANDATE_STREAM_UI_ORIGIN", tc.config)
		r := httptest.NewRequest("GET", "/api/logs/stream", nil)
		r.Header.Set("Origin", tc.origin)
		if tc.session {
			session := streamSession{time.Now().Add(time.Minute), func(context.Context) bool { return true }}
			r = r.WithContext(context.WithValue(r.Context(), streamSessionKey{}, session))
		}
		w := httptest.NewRecorder()
		cors(authenticatedStream(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
		if got := w.Header().Get("Access-Control-Allow-Origin"); (got == ui) != tc.allowed || (!tc.allowed && got != "") {
			t.Fatalf("%+v: allowed origin %q", tc, got)
		}
		if (w.Header().Get("Access-Control-Allow-Credentials") == "true") != tc.allowed {
			t.Fatalf("%+v: wrong credential policy", tc)
		}
	}
}
