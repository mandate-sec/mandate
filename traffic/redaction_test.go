package traffic

import (
	"strings"
	"testing"
)

func TestCaptureRedactsSensitiveHeaderValues(t *testing.T) {
	headers := map[string][]string{"Content-Type": {"application/json"}}
	for _, key := range []string{"authorization", "COOKIE", "Set-Cookie", "X-Api-Key", "Proxy-Authorization"} {
		headers[key] = []string{"private-value", "second-private-value"}
	}
	got := headerLines(headers)
	if strings.Contains(got, "private-value") || strings.Count(got, "[REDACTED]") != 5 || !strings.Contains(got, "application/json") {
		t.Fatal("unexpected captured header redaction")
	}
}
