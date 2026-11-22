package server

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Credentials in URLs are easily retained in access logs and browser history.
func extractToken(r *http.Request) string {
	if headers := r.Header.Values("Authorization"); len(headers) > 0 {
		// An explicit credential must stand on its own, even if the browser
		// also attached an administrator's session cookie.
		if len(headers) != 1 {
			return ""
		}
		scheme, credential, ok := strings.Cut(headers[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return ""
		}
		return strings.TrimLeft(credential, " ")
	}
	if cookie, err := r.Cookie("artex_token"); err == nil {
		return cookie.Value
	}
	return ""
}

func streamUIOrigin() string {
	origin := os.Getenv("MANDATE_STREAM_UI_ORIGIN")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || origin != u.Scheme+"://"+u.Host || u.User != nil {
		return ""
	}
	return origin
}

func cors(next http.Handler) http.Handler {
	guard := http.NewCrossOriginProtection()
	return guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	}))
}
