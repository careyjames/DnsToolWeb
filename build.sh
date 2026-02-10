#!/bin/sh
set -e
CGO_ENABLED=0 go build -o dns-tool-server ./go-server/cmd/server/
echo "Build complete: dns-tool-server"
ls -la dns-tool-server
