package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStreamExpiryClosesHTTPResponse(t *testing.T) {
	handler := authenticatedStream(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "initial event")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		_, _ = io.WriteString(w, "expired event")
	})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := streamSession{time.Now().Add(100 * time.Millisecond), func(context.Context) bool { return true }}
		handler(w, r.WithContext(context.WithValue(r.Context(), streamSessionKey{}, session)))
	}))
	defer s.Close()
	client := s.Client()
	client.Timeout = 3 * time.Second
	resp, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "initial event" {
		t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}

func TestStreamRevocationCancelsOnlyAfterFailedCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	checks := 0
	watchStreamSession(ctx, cancel, func(checkCtx context.Context) bool {
		if _, ok := checkCtx.Deadline(); !ok {
			t.Fatal("missing database timeout")
		}
		checks++
		return checks == 1
	}, time.Millisecond)
	if ctx.Err() != context.Canceled || checks != 2 {
		t.Fatalf("checks=%d context error=%v", checks, ctx.Err())
	}
}

func TestStreamRejectsMissingSession(t *testing.T) {
	w := httptest.NewRecorder()
	authenticatedStream(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected stream") })(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatal(w.Code)
	}
}
