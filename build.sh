#!/bin/sh
set -e
echo "BUILD: pwd is $(pwd)"
ls go-server/go.mod
cd go-server
go build -o dns-tool-server ./cmd/server/
echo "BUILD: binary at go-server/dns-tool-server"
ls -la dns-tool-server
