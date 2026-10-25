#!/bin/sh
# Cross-build for Keenetic Hopper (mipsle, softfloat). Run from the project root.
set -eu
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
mkdir -p dist
GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
  -o dist/xkeen-ui-linux-mipsle ./cmd/xkeen-ui
( cd dist && sha256sum xkeen-ui-linux-mipsle > xkeen-ui-linux-mipsle.sha256 )
ls -l dist
