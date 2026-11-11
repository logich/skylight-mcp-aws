#!/usr/bin/env bash
# Build the Lambda binary (static, linux/arm64) into dist/lambda/bootstrap.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(git describe --always --dirty 2>/dev/null || echo dev)"
rm -rf dist/lambda
mkdir -p dist/lambda
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
  -o dist/lambda/bootstrap ./cmd/server
echo "built dist/lambda/bootstrap (version ${VERSION})"
file dist/lambda/bootstrap
