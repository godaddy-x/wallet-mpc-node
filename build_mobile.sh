#!/bin/bash
# Build wallet-mpc-node/mobile as an Android AAR via gomobile (single ABI per invocation).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/output"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-34}"
LDFLAGS="${LDFLAGS:--s -w}"
# 64-bit ABIs only: freego v1.1.30 ormx/sqld does not compile on 32-bit Android (int overflow).
ANDROID_TARGETS="${ANDROID_TARGETS:-android/arm64}"

default_aar_name() {
  case "${1}" in
    android/arm64) echo "wallet-mpc-node-arm64.aar" ;;
    android/amd64) echo "wallet-mpc-node-x86_64.aar" ;;
    *) echo "wallet-mpc-node.aar" ;;
  esac
}

if [[ "${ANDROID_TARGETS}" == *","* ]]; then
  echo "ANDROID_TARGETS must be a single ABI (got: ${ANDROID_TARGETS})" >&2
  echo "Use: bash build_mobile_all.sh" >&2
  exit 1
fi

AAR_NAME="${AAR_NAME:-$(default_aar_name "${ANDROID_TARGETS}")}"

if [[ -z "${MOBILE_VERSION:-}" ]]; then
  MOBILE_VERSION="$(go list -m -f '{{.Version}}' golang.org/x/mobile 2>/dev/null || true)"
fi
MOBILE_VERSION="${MOBILE_VERSION:-v0.0.0-20260803200217-62cee1672c8e}"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  if [[ -n "${ANDROID_HOME:-}" ]] && [[ -d "${ANDROID_HOME}/ndk" ]]; then
    # Pick the newest installed NDK (gomobile + NDK r26+ supports -androidapi 21..34).
    ANDROID_NDK_HOME="$(find "${ANDROID_HOME}/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
    export ANDROID_NDK_HOME
  fi
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  echo "ANDROID_NDK_HOME is not set and no NDK found under ANDROID_HOME/ndk" >&2
  echo "Install NDK and set -androidapi (21..34), e.g.:" >&2
  echo "  sdkmanager \"ndk;26.1.10909125\"" >&2
  exit 1
fi

if [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
  echo "ANDROID_NDK_HOME is not a directory: ${ANDROID_NDK_HOME}" >&2
  exit 1
fi

if [[ -n "${ANDROID_HOME:-}" ]]; then
  export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
fi
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-$ANDROID_NDK_HOME}"

mkdir -p "$OUT"

export PATH="$(go env GOPATH)/bin:$PATH"

echo "--- install gomobile ${MOBILE_VERSION} ---"
go install "golang.org/x/mobile/cmd/gomobile@${MOBILE_VERSION}"
go install "golang.org/x/mobile/cmd/gobind@${MOBILE_VERSION}"

echo "--- gomobile init ---"
gomobile init

echo "--- gomobile bind ${ANDROID_TARGETS} (api ${ANDROID_API_LEVEL}) -> ${OUT}/${AAR_NAME} ---"
cd "$ROOT"
gomobile bind \
  -ldflags="${LDFLAGS}" \
  -trimpath \
  -target="${ANDROID_TARGETS}" \
  -androidapi="${ANDROID_API_LEVEL}" \
  -o "${OUT}/${AAR_NAME}" \
  ./mobile

if [[ ! -f "${OUT}/${AAR_NAME}" ]]; then
  echo "gomobile bind finished but ${OUT}/${AAR_NAME} is missing" >&2
  exit 1
fi

echo ""
echo "Done: ${OUT}/${AAR_NAME}"
ls -lh "${OUT}/${AAR_NAME}"
