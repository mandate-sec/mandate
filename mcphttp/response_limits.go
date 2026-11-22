package mcphttp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const maxMCPResponseBytes = 8 << 20

var errMCPResponseSize = errors.New("MCP response exceeds size limit")

func boundedSSELine(r *bufio.Reader, limit int) (string, error) {
	var line strings.Builder
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > limit-line.Len() {
			return "", errMCPResponseSize
		}
		line.Write(fragment)
		if err != bufio.ErrBufferFull {
			return line.String(), err
		}
	}
}

func decodeRPCResponse(r io.Reader) (*rpcResponse, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxMCPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMCPResponseBytes {
		return nil, errMCPResponseSize
	}
	var out rpcResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("mcp: decode json response: %w", err)
	}
	return &out, nil
}
