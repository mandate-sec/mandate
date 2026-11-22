#!/usr/bin/env bash
# Development mode runs the backend, recording proxy and web UI on loopback.
# The frontend proxies /api to the backend; Ctrl-C exits everything.
#
# For the single-binary (embedded frontend) approach, see the "single binary" section of the README; it does not use this script.
set -euo pipefail
cd "$(dirname "$0")"

# On exit, terminate all child processes in this process group (backend + frontend).
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Backend (plain go run, no embedded frontend); the number of concurrent work agents is configured in "System Settings".
MANDATE_STREAM_UI_ORIGIN=http://127.0.0.1:3000 go run ./cmd/artex -listen 127.0.0.1:8787 -proxy 127.0.0.1:8788 &

# Frontend hot reload (Vite/Next dev server, /api proxied to :8787).
( cd web && npm run dev ) &

echo "[dev] backend 127.0.0.1:8787 / proxy 127.0.0.1:8788 / frontend http://127.0.0.1:3000 (Ctrl-C to exit)"
wait
