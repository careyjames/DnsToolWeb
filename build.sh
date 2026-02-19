#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

cd "$SCRIPT_DIR/go-server"
GONOSUMCHECK=1 GIT_DIR=/dev/null go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "$LDFLAGS" \
  -o /tmp/dns-tool-new \
  ./cmd/server/
cd "$SCRIPT_DIR"
mv /tmp/dns-tool-new dns-tool-server-new
mv dns-tool-server-new dns-tool-server
echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
