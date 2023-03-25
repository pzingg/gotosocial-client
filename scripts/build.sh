#!/bin/sh

set -eu

# DEBUG returns whether DEBUG build is enabled.
DEBUG() { [ ! -z "${DEBUG-}" ]; }

# Build `client` binary, setting main.Version to git information.
CGO_ENABLED=0 go build -trimpath \
                       -tags "$(DEBUG && echo 'debugenv')" \
                       -ldflags="-s -w -extldflags '-static' -X 'main.Version=${VERSION:-$(git describe --tags --abbrev=0)}'" \
                       ./cmd/client
