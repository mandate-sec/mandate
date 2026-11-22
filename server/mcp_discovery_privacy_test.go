package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestMCPDiscoveryFailurePrivacy(t *testing.T) {
	const marker = "private-fixture"
	for _, transport := range []string{"http", "sse"} {
		t.Run(transport, func(t *testing.T) {
			served := make(chan struct{}, 1)
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case served <- struct{}{}:
				default:
				}
				http.Error(w, marker, http.StatusForbidden)
			}))
			defer endpoint.Close()
			record := &db.MCPServer{Transport: transport, URL: endpoint.URL + "/?key=" + marker}
			err := new(Server).discoverAndCacheMCP(context.Background(), record)
			if len(served) == 0 || err == nil || strings.Contains(err.Error(), marker) {
				t.Fatalf("expected a sanitized discovery failure after a request, got %v", err)
			}
		})
	}
}
