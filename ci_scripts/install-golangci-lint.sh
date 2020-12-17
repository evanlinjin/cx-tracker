#!/usr/bin/env bash

set -e -o pipefail

if [[ -z "$VERSION" ]]; then
	VERSION="latest"
fi

if [[ "$VERSION" != "latest" ]]; then
  VERSION="v$VERSION"
fi

if [[ -z "${GOBIN}" ]]; then export GOBIN=$HOME/go/bin; fi
echo "GOBIN=${GOBIN}"

# In alpine linux (as it does not come with curl by default)
wget -O - -q https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b "${GOBIN}" "${VERSION}"

golangci-lint --version