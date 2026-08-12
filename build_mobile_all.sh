#!/bin/bash
# Build both Android AAR variants: arm64 (devices) and x86_64 (emulators).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

ANDROID_TARGETS=android/arm64 AAR_NAME=wallet-mpc-node-arm64.aar bash "$ROOT/build_mobile.sh"
ANDROID_TARGETS=android/amd64 AAR_NAME=wallet-mpc-node-x86_64.aar bash "$ROOT/build_mobile.sh"

echo ""
echo "All mobile AARs:"
ls -lh "$ROOT/output"/wallet-mpc-node-*.aar
