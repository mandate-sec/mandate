package mcphttp

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMCPCredentialDestinations(t *testing.T) {
	const base = "https://example.test/mcp/stream"
	start, err := http.NewRequest("GET", base, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		endpoint string
		allow    bool
	}{
		{"message?id=12", true},
		{"https://EXAMPLE.test:443/message", true},
		{"//elsewhere.test/message", false},
		{"https://api.example.test/message", false},
		{"https://example.test:8443/message", false},
		{"http://example.test/message", false},
		{"https://account@example.test/message", false},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			resolved, err := start.URL.Parse(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			redirectErr := checkMCPRedirect(&http.Request{URL: resolved}, []*http.Request{start})
			got, endpointErr := readSSEEndpoint(bufio.NewReader(strings.NewReader("data: "+tc.endpoint+"\n")), base)
			if (redirectErr == nil) != tc.allow || (endpointErr == nil) != tc.allow || tc.allow && got != resolved.String() {
				t.Fatalf("redirect=%v endpoint=%v resolved=%q", redirectErr, endpointErr, got)
			}
		})
	}
	a, _ := url.Parse("http://[fe80::1%25Zone]/")
	b, _ := url.Parse("http://[fe80::1%25zone]/")
	if sameMCPOrigin(a, b) {
		t.Fatal("different IPv6 zones treated as one origin")
	}
}
