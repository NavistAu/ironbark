#!/usr/bin/env bash
# Builds the voidstar plugin (grant-model branch) into test/integration/plugins/
# for the OpenBao container's -dev-plugin-dir. Override the source with
# VOIDSTAR_SRC. The default resolves against the main checkout of ironbark, so
# it also works from a git worktree.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
main=$(cd "$(git -C "$here" rev-parse --path-format=absolute --git-common-dir)/.." && pwd)
src=${VOIDSTAR_SRC:-$main/../openbao-plugin-secrets-voidstar/.worktrees/grant-model}
src=$(cd "$src" && pwd)
case "$(docker info --format '{{.Architecture}}')" in aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
mkdir -p "$here/plugins"
docker run --rm -v "$src":/src:ro -v "$here/plugins":/out -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=$arch -e GOFLAGS=-buildvcs=false \
  golang:1.25-alpine go build -o /out/openbao-plugin-secrets-voidstar ./cmd/openbao-plugin-secrets-voidstar
echo "built $here/plugins/openbao-plugin-secrets-voidstar from $src"
