#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/go-server"
GONOSUMCHECK=1 GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/
cd "$SCRIPT_DIR"
mv /tmp/dns-tool-new dns-tool-server-new
mv dns-tool-server-new dns-tool-server
echo "Build complete: dns-tool-server"
ls -la dns-tool-server
