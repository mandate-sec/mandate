package enrich

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientRejectsUntrustedCertificate(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("HTTP request reached a server with an untrusted certificate")
	}))
	defer endpoint.Close()
	resp, err := buildClient(nil).Get(endpoint.URL)
	if resp != nil {
		resp.Body.Close()
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected untrusted certificate rejection, got %v", err)
	}
}
