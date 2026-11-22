package mcphttp

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResponseBounds(t *testing.T) {
	const response = `{"jsonrpc":"2.0","id":1,"result":{}}`
	full := response + strings.Repeat(" ", maxMCPResponseBytes-len(response))
	if got, err := decodeRPCResponse(strings.NewReader(full)); err != nil || got.ID != 1 {
		t.Fatal("exact-limit response rejected", err)
	}
	if _, err := decodeRPCResponse(strings.NewReader(full + " ")); !errors.Is(err, errMCPResponseSize) {
		t.Fatal("oversized JSON response accepted", err)
	}
	line := "data:" + strings.Repeat("x", 1024) + "\n"
	if _, err := parseSSE(strings.NewReader(strings.Repeat(line, maxMCPResponseBytes/1024+1)), 1); !errors.Is(err, errMCPResponseSize) {
		t.Fatal("oversized multiline event accepted", err)
	}
	if _, err := readSSEEndpoint(bufio.NewReader(strings.NewReader(strings.Repeat(":x\n", 22000))), "https://example.test"); !errors.Is(err, errMCPResponseSize) {
		t.Fatal("oversized endpoint announcement accepted", err)
	}
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 128)+"\n"), 16)
	if _, err := boundedSSELine(reader, 128); !errors.Is(err, errMCPResponseSize) {
		t.Fatal("oversized legacy event line accepted", err)
	}
}

func TestCancelWaitingForSSEEndpoint(t *testing.T) {
	connected := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		close(connected)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer s.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewSSE(ctx, "fixture", s.URL, nil, false)
		done <- err
	}()
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture connection timed out")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("initialization ignored cancellation")
	}
}
