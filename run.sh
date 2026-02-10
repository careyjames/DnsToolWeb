#!/bin/bash
echo "Starting Go DNS Tool server on port 5000..."
cd /home/runner/workspace/go-server && go run ./cmd/server/
