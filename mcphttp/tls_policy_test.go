package mcphttp

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacySettingsCannotDisableTLSVerification(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("HTTP request reached a server with an untrusted certificate")
	}))
	defer endpoint.Close()
	for name, connect := range map[string]func(context.Context, string, string, map[string]string, bool) (*Client, error){"http": New, "sse": NewSSE} {
		t.Run(name, func(t *testing.T) {
			_, err := connect(t.Context(), "local fixture", endpoint.URL, nil, true)
			var unknown x509.UnknownAuthorityError
			if !errors.As(err, &unknown) {
				t.Fatalf("expected untrusted certificate rejection, got %v", err)
			}
		})
	}
}
