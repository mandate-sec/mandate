package contextio

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type cancelingReader struct {
	cancel context.CancelFunc
	source *strings.Reader
}

func (r cancelingReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p[:1])
	r.cancel()
	return n, err
}

func TestCopyStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dest bytes.Buffer
	n, err := Copy(ctx, &dest, cancelingReader{cancel, strings.NewReader("evidence")})
	if !errors.Is(err, context.Canceled) || n != 1 || dest.String() != "e" {
		t.Fatalf("copied %d bytes (%q), got %v", n, dest.String(), err)
	}
}
