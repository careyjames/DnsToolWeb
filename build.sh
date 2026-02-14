#!/bin/sh
set -e
cd /home/runner/workspace/go-server
GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/
cd /home/runner/workspace
mv /tmp/dns-tool-new dns-tool-server-new
mv dns-tool-server-new dns-tool-server
echo "Build complete: dns-tool-server"
ls -la dns-tool-server
