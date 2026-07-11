#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/output"
LDFLAGS="-s -w"
BIN_PREFIX="wallet-mpc-node"

rm -rf "$OUT"
mkdir -p "$OUT"

build_one() {
  local goos=$1 goarch=$2 out_name=$3
  echo ""
  echo "--- build ${goos}/${goarch} ---"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -installsuffix cgo -ldflags="$LDFLAGS" -o "$OUT/$out_name" ./cmd/wallet-mpc-node
}

compress_upx() {
  local f=$1
  if ! command -v upx >/dev/null 2>&1; then
    echo "UPX not installed, skip ${f}"
    return 0
  fi
  echo ""
  echo "--- UPX ${f} ---"
  upx --best --lzma "$f" || echo "warning: UPX skipped ${f}"
}

build_one linux amd64 "${BIN_PREFIX}-linux-amd64"
build_one linux arm64 "${BIN_PREFIX}-linux-arm64"
build_one darwin amd64 "${BIN_PREFIX}-darwin-amd64"
build_one darwin arm64 "${BIN_PREFIX}-darwin-arm64"
build_one windows amd64 "${BIN_PREFIX}-windows-amd64.exe"

shopt -s nullglob
for f in "$OUT"/${BIN_PREFIX}-*; do
  compress_upx "$f"
done

echo ""
echo "Done. Binaries in output/:"
ls -lh "$OUT"
