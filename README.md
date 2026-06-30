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
├── examples/                        # cli_node*.example.json
├── mpc/
│   ├── alg_ecdsa/                   # CGGMP
│   ├── alg_ed25519/                 # FROST
│   ├── hd/                          # HD derivation
│   ├── ecdsa/, ed25519/             # on-chain verify helpers
├── build_release.bat, build_release.sh
└── .github/workflows/release.yml   # tag → Release + SHA256SUMS
```

## Official releases

Download pre-built binaries **only** from **[GitHub Releases](https://github.com/godaddy-x/wallet-mpc-node/releases)**. Pushing a tag `v*` runs [`build_release.sh`](build_release.sh) via Actions (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"` — stripped static binaries, smaller than a plain `go build`):

| Asset | Platform |
|-------|----------|
| `wallet-mpc-node-linux-amd64` | Linux x86_64 |
| `wallet-mpc-node-linux-arm64` | Linux ARM64 |
| `wallet-mpc-node-darwin-amd64` | macOS Intel (x86_64) |
| `wallet-mpc-node-darwin-arm64` | macOS Apple Silicon (ARM64) |
| `wallet-mpc-node-windows-amd64.exe` | Windows x86_64 |
| `SHA256SUMS` | SHA-256 checksums for all binaries above |

**Verify** before deployment:

```bash
# Linux / macOS — check files present in the download folder
sha256sum -c --ignore-missing SHA256SUMS
```

```powershell
# Windows — compare with the line for wallet-mpc-node-windows-amd64.exe in SHA256SUMS
Get-FileHash .\wallet-mpc-node-windows-amd64.exe -Algorithm SHA256
```

Maintainers — publish a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## Build and run

> ℹ️ **Production deployments:** use pre-built binaries from [Official releases](#official-releases) above. The steps below are for local development and debugging.

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
| darwin/amd64 | `output/wallet-mpc-node-darwin-amd64` |
| darwin/arm64 | `output/wallet-mpc-node-darwin-arm64` |
| windows/amd64 | `output/wallet-mpc-node-windows-amd64.exe` |

Manual example (linux/amd64):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o output/wallet-mpc-node-linux-amd64 .
```

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

Copy [`examples/cli_node0.example.json`](examples/cli_node0.example.json) to `cli_node0.json` (gitignored) and fill in values from broker **`nodeBindings`**. For production TEE, omit `clientPrk` / `keystoreKey` from JSON and inject via env — see [`examples/cli_node.prod.example.json`](examples/cli_node.prod.example.json).

| Field | Required | Description |
|-------|----------|-------------|
| `domain` | yes | Broker node WebSocket host (`host:port`, broker `port+100`) |
| `source` | yes | Node ID (`node0`, `node1`, …) — must match broker `nodeBindings` |
| `keyPath` | yes | WS route after login (default `/ws/key`) |
| `loginPath` | yes | Plan2 login route (default `/ws/login`) |
| `clientNo` | yes | Plan2 client number from broker `nodeBindings` |
| `serverPub` | yes | Broker ML-DSA-87 public key |
| `clientPrk` | yes* | Node ML-DSA-87 private key (*prod: `MPC_NODE_CLIENT_PRK` env) |
| `broadcastKey` | yes | Push signature key (hex); must match broker |
| `keystoreKey` | yes* | Shard at-rest encryption key (*prod: `MPC_KEYSTORE_KEY` env) |
| `shardKeysDir` | no | Shard directory (default `keys`; overridden by `-keysdir`) |

<details>
<summary><code>cli_node0.json</code> — minimum example</summary>

```json
{
  "domain": "127.0.0.1:9522",
  "source": "node0",
  "keyPath": "/ws/key",
  "loginPath": "/ws/login",
  "clientNo": 0,
  "clientPrk": "REPLACE_WITH_ML-DSA-87_PRIVATE_KEY",
  "serverPub": "REPLACE_WITH_BROKER_NODEBINDING_PUBLIC_KEY",
  "broadcastKey": "REPLACE_WITH_BROKER_PUSH_BROADCAST_KEY_HEX",
  "keystoreKey": "REPLACE_WITH_SHARD_ENCRYPTION_KEY",
  "shardKeysDir": "keys"
}
```

</details>

## Dependencies

Direct dependencies (per `go.mod`). All listed licenses are **compatible with GPL-3.0** distribution of this project.

| Repository | License | Purpose |
|------------|---------|---------|
| [getamis/alice](https://github.com/getamis/alice) | Apache-2.0 | CGGMP (ECDSA) · FROST (Ed25519) |
| [godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | MIT | ML-KEM-1024 · ML-DSA-87 |
| [godaddy-x/freego](https://github.com/godaddy-x/freego) | MIT | WebSocket / utilities |
| [godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | MIT | HD derivation types |

## License

GPL-3.0
