package traffic

import (
	"net/url"
	"strings"
)

// Redact a copy at the capture boundary. Never modify a forwarded request.
func captureURL(original *url.URL) url.URL {
	u := *original
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	if u.Opaque != "" {
		u.Opaque = ""
		u.Path, u.RawPath = "/redacted", ""
	}
	if u.RawQuery != "" {
		u.RawQuery = "redacted"
	}
	return u
}

func headerLines(h map[string][]string) string {
	var b strings.Builder
	for k, vs := range h {
		switch strings.ToLower(k) {
		case "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization",
			"referer", "location", "content-location", "link", "refresh", "x-original-url", "x-rewrite-url":
			vs = []string{"[REDACTED]"}
		}
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
