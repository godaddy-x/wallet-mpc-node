#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/output"
LDFLAGS="-s -w"

rm -rf "$OUT"
mkdir -p "$OUT"

build_one() {
  local goos=$1 goarch=$2 out_name=$3
  echo ""
  echo "--- build ${goos}/${goarch} ---"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -installsuffix cgo -ldflags="$LDFLAGS" -o "$OUT/$out_name" .
}

build_one linux amd64 wallet-mpc-node-linux-amd64
build_one linux arm64 wallet-mpc-node-linux-arm64
build_one darwin amd64 wallet-mpc-node-darwin-amd64
build_one darwin arm64 wallet-mpc-node-darwin-arm64
build_one windows amd64 wallet-mpc-node-windows-amd64.exe

echo ""
echo "Done. Binaries in output/:"
ls -lh "$OUT"
