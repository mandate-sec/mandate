package contextio

import (
	"context"
	"io"
)

// Copy checks ctx between reads. A read already in progress may still complete.
func Copy(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, reader{ctx, src})
}

type reader struct {
	ctx context.Context
	src io.Reader
}

func (r reader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.src.Read(p)
}
