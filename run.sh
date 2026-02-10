#!/bin/bash
set -e
echo "Starting Go DNS Tool server on port 5000..."
cd /home/runner/workspace
exec go run ./go-server/cmd/server/
