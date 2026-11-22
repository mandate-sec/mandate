package traffic

import (
	"net/url"
	"strings"
	"testing"
)

func TestCaptureRedactsSensitiveHeaderValues(t *testing.T) {
	headers := map[string][]string{"Content-Type": {"application/json"}}
	keys := []string{"authorization", "COOKIE", "Set-Cookie", "X-Api-Key", "Proxy-Authorization", "Referer", "LOCATION", "Content-Location", "Link", "Refresh", "X-Original-Url", "X-Rewrite-URL"}
	for _, key := range keys {
		headers[key] = []string{"private-value", "second-private-value"}
	}
	got := headerLines(headers)
	if strings.Contains(got, "private-value") || strings.Count(got, "[REDACTED]") != len(keys) || !strings.Contains(got, "application/json") {
		t.Fatal("unexpected captured header redaction")
	}
}

func TestCaptureURLRedactsBeforeFormatting(t *testing.T) {
	for _, tc := range []struct{ input, full, request string }{
		{"https://alice:secret@sample.test:8443/a%2Fb?unknown=secret&bad=%ZZ#private", "https://sample.test:8443/a%2Fb?redacted", "/a%2Fb?redacted"},
		{"https://sample.test/path", "https://sample.test/path", "/path"},
		{"custom:private?key=secret", "custom:///redacted?redacted", "/redacted?redacted"},
	} {
		u, err := url.Parse(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		before := u.String()
		got := captureURL(u)
		if got.String() != tc.full || got.RequestURI() != tc.request || u.String() != before {
			t.Errorf("capture URL %q, request URI %q, original preserved %v", got.String(), got.RequestURI(), u.String() == before)
		}
	}
}
