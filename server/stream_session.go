package server

import (
	"context"
	"net/http"
	"time"
)

type streamSessionKey struct{}

type streamSession struct {
	expires time.Time
	current func(context.Context) bool
}

type sessionStreamWriter struct {
	http.ResponseWriter
	flusher http.Flusher
	ctx     context.Context
}

func (w sessionStreamWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(data)
}

func (w sessionStreamWriter) Flush() {
	if w.ctx.Err() == nil {
		w.flusher.Flush()
	}
}

// Long-lived responses must recheck the generation shared by all console instances.
func authenticatedStream(next http.HandlerFunc) http.HandlerFunc {
	origin := streamUIOrigin()
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := r.Context().Value(streamSessionKey{}).(streamSession)
		if !ok || session.current == nil || !time.Now().Before(session.expires) {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unavailable", http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), session.expires)
		defer cancel()
		if origin != "" && r.Method == http.MethodGet && r.Header.Get("Origin") == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		go watchStreamSession(ctx, cancel, session.current, 15*time.Second)
		next(sessionStreamWriter{w, flusher, ctx}, r.WithContext(ctx))
	}
}

func watchStreamSession(ctx context.Context, cancel context.CancelFunc, current func(context.Context) bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			valid := current(checkCtx)
			stop()
			if !valid {
				cancel()
				return
			}
		}
	}
}
