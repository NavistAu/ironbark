#!/usr/bin/env bash
# Puts the voidstar plugin into test/integration/plugins/ for the OpenBao
# container's -dev-plugin-dir. By default it downloads the public release
# VOIDSTAR_VERSION for the Docker host's architecture and checks it against the
# release's .sha256 asset. Set VOIDSTAR_SRC to a voidstar checkout to build from
# source instead.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
version=${VOIDSTAR_VERSION:-0.2.0}
case "$(docker info --format '{{.Architecture}}')" in aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
mkdir -p "$here/plugins"
if [ -n "${VOIDSTAR_SRC:-}" ]; then
  src=$(cd "$VOIDSTAR_SRC" && pwd)
  docker run --rm -v "$src":/src:ro -v "$here/plugins":/out -w /src \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=$arch -e GOFLAGS=-buildvcs=false \
    golang:1.25-alpine go build -o /out/openbao-plugin-secrets-voidstar ./cmd/openbao-plugin-secrets-voidstar
  echo "built $here/plugins/openbao-plugin-secrets-voidstar from $src"
  exit 0
fi
tarball=openbao-plugin-secrets-voidstar_${version}_linux_${arch}.tar.gz
url=https://github.com/NavistAu/openbao-plugin-secrets-voidstar/releases/download/v${version}/${tarball}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$tarball" "$url"
curl -fsSL -o "$tmp/$tarball.sha256" "$url.sha256"
want=$(awk '{print $1}' "$tmp/$tarball.sha256")
got=$( (sha256sum "$tmp/$tarball" 2>/dev/null || shasum -a 256 "$tmp/$tarball") | awk '{print $1}')
[ "$want" = "$got" ] || { echo "checksum mismatch for $tarball: want $want, got $got" >&2; exit 1; }
tar -xzf "$tmp/$tarball" -C "$here/plugins" openbao-plugin-secrets-voidstar
echo "fetched voidstar v$version ($arch) into $here/plugins"
