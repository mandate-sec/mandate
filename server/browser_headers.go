package server

import (
	"net/http"
	"strings"
)

func consoleBrowserHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		policy := "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
		if strings.HasPrefix(r.URL.Path, "/api/") {
			policy += "; sandbox; default-src 'none'; form-action 'none'"
		}
		h.Set("Content-Security-Policy", policy)
		next.ServeHTTP(w, r)
	})
}
