#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/go-server" && go build -o "$SCRIPT_DIR/dns-tool-server" ./cmd/server/
