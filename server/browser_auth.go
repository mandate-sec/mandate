package server

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Credentials in URLs are easily retained in access logs and browser history.
func extractToken(r *http.Request) string {
	if header, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return header
	}
	if cookie, err := r.Cookie("artex_token"); err == nil {
		return cookie.Value
	}
	return ""
}

func cors(next http.Handler) http.Handler {
	origin := os.Getenv("MANDATE_STREAM_UI_ORIGIN")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || origin != u.Scheme+"://"+u.Host || u.User != nil {
		origin = ""
	}
	guard := http.NewCrossOriginProtection()
	return guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		if origin != "" && r.Header.Get("Origin") == origin && r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	}))
}
