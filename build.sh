#!/bin/sh
set -e
echo "BUILD: pwd is $(pwd)"
echo "BUILD: listing go-server/"
ls go-server/go.mod
cd go-server
go build -o ../dns-tool-server ./cmd/server/
echo "BUILD: binary created"
ls -la ../dns-tool-server
