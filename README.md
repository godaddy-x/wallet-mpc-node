# wallet-mpc-node

<p align="center">
  <a href="./README.md"><strong>English</strong></a>
  ·
  <a href="./README.zh.md">简体中文</a>
  ·
  <a href="./README.zh-TW.md">繁體中文</a>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Open-source **MPC signing node** (GPL-3.0). Connects to **wallet-mpc-broker** (closed source), runs threshold Keygen / Refresh / Sign locally (**ECDSA · CGGMP** or **Ed25519 · FROST**), encrypts protocol traffic with ML-KEM-1024, and persists encrypted shards on disk.

> [!CAUTION]
> **Do NOT build or run binaries from third-party, forked, or unverified source.** This process holds MPC key shards; a tampered build can exfiltrate secrets or break threshold security. Use **official wallet-mpc-broker builds only** (closed source — not from a public repo).

## Node vs broker

| | **wallet-mpc-node** (this repo) | **wallet-mpc-broker** |
|---|---|---|
| **Role** | Signing node; holds and computes shards | Coordinator / CLI; orchestrates Keygen / Sign |
| **License** | GPL-3.0 · **open source** | Proprietary · **closed source** |
| **Build** | `go build` from this repository | Official distribution only |

## Signing algorithms

Keygen and Sign are routed by the **`algorithm`** field on broker session DTOs (`ecdsa` | `ed25519`):

| ID | On-chain | Protocol | Package |
|----|----------|----------|---------|
| `ecdsa` | secp256k1 ECDSA | CGGMP | `mpc/alg_ecdsa/` |
| `ed25519` | Ed25519 (EdDSA) | FROST | `mpc/alg_ed25519/` |

- Root pubkey hex infers algorithm: 65-byte uncompressed → `ecdsa`; 32-byte → `ed25519`.
- HD derivation for both curves: `mpc/hd/`.
- Wallet `algorithm` comes from broker KeyMeta; nodes do not choose it locally.
- ML-KEM end-to-end encryption applies to both stacks; the broker cannot decrypt WireBytes.

> **Deployment:** broker and all nodes must run the **same version** (ML-KEM-1024 wire protocol).

## Directory layout

```text
.
├── main.go, config.go, entry.go
├── mpc_keygen.go, mpc_sign.go       # route by algorithm
├── mpc_ecdsa.go, mpc_ed25519.go     # CGGMP / FROST flows
├── connect/                         # WebSocket SDK
├── dto/                             # protocol DTOs (broker ↔ node)
├── mpc/
│   ├── alg_ecdsa/                   # CGGMP
│   ├── alg_ed25519/                 # FROST
│   ├── hd/                          # HD derivation
│   ├── ecdsa/, ed25519/             # on-chain verify helpers
├── build_release.bat, build_release.sh
```

## Build and run

**Requirements:** Go 1.26+

**Quick build:**

```bash
go build -o wallet-mpc-node .
```

**Cross-compile** (static, `CGO_ENABLED=0` → `output/`):

```bat
build_release.bat          REM Windows
```

```bash
chmod +x build_release.sh && ./build_release.sh   # Linux / macOS
```

| Platform | Output |
|----------|--------|
| linux/amd64 | `output/wallet-mpc-node-linux-amd64` |
| linux/arm64 | `output/wallet-mpc-node-linux-arm64` |
| windows/amd64 | `output/wallet-mpc-node-windows-amd64.exe` |

Manual example (linux/amd64):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o output/wallet-mpc-node-linux-amd64 .
```

Optional [UPX](https://upx.github.io/) compression (`upx --best --lzma output/...`) reduces size; some AV tools may flag packed binaries.

**Run** (one config per node, e.g. `cli_node0.json`):

```bash
./wallet-mpc-node -config=cli_node0.json
./wallet-mpc-node -config=cli_node0.json -keysdir=./data/shards -logdir=./logs
```

Production TEE (override secrets via env, not JSON):

```bash
export MPC_NODE_CLIENT_PRK=<tee-unsealed>   # Windows cmd: set MPC_NODE_CLIENT_PRK=...
export MPC_KEYSTORE_KEY=<tee-unsealed>
./wallet-mpc-node -config=cli_node0.json
```

## Configuration

| Item | Description |
|------|-------------|
| `cli_nodeN.json` | Broker host, WebSocket, ML-DSA auth, `shardKeysDir` |
| `-keysdir` | Shard directory (overrides JSON; default `keys`) |
| `MPC_KEYSTORE_KEY` / `keystoreKey` | Shard encryption key (required; plaintext shards not supported) |

## Dependencies

| Repository | Purpose |
|------------|---------|
| [getamis/alice](https://github.com/getamis/alice) | CGGMP (ECDSA) · FROST (Ed25519) |
| [godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | ML-KEM-1024 · ML-DSA-87 |
| [godaddy-x/freego](https://github.com/godaddy-x/freego) | WebSocket / utilities |
| [godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | HD derivation types |

## License

GPL-3.0
