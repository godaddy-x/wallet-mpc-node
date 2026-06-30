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
    go build -installsuffix cgo -ldflags="$LDFLAGS" -o "$OUT/$out_name" .
}

build_one linux amd64 wallet-mpc-node-linux-amd64
build_one linux arm64 wallet-mpc-node-linux-arm64
build_one windows amd64 wallet-mpc-node-windows-amd64.exe

echo ""
echo "Done. Binaries in output/:"
ls -lh "$OUT"
echo ""
echo "[Optional] If binary size matters, compress with UPX (step 2):"
echo "  upx --best --lzma output/wallet-mpc-node-linux-amd64"
echo "  upx --best --lzma output/wallet-mpc-node-linux-arm64"
echo "  upx --best --lzma output/wallet-mpc-node-windows-amd64.exe"
echo ""
echo "UPX is not required for build or runtime. Some AV tools may flag packed binaries."
