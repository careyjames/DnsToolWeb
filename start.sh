#!/bin/bash
cd /home/runner/workspace
go build -C go-server -o ../dns-tool-server ./cmd/server/
exec ./dns-tool-server
