#!/bin/bash
set -e

echo "Building Go DNS Tool server..."
cd /home/runner/workspace
go build -buildvcs=false -o dns-tool-server ./go-server/cmd/server/

echo "Starting Go DNS Tool server on port 5000..."
exec ./dns-tool-server
