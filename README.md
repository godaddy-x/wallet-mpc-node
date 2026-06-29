# wallet-mpc-node

<p align="center">
  <a href="./README.md"><strong>English</strong></a>
  ·
  <a href="./README.zh.md">简体中文</a>
  ·
  <a href="./README.zh-TW.md">繁體中文</a>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

MPC TSS node process: connects to the [wallet-mpc-broker](https://github.com/godaddy-x/wallet-mpc-broker) WebSocket, participates in CGGMP threshold key generation and signing; MPC protocol messages are encrypted with ML-KEM-1024, and shards are stored locally on disk.

| | |
|---|---|
| **Module path** | `github.com/godaddy-x/wallet-mpc-node` |
| **Companion repo** | [wallet-mpc-broker](https://github.com/godaddy-x/wallet-mpc-broker) (coordinator / CLI) |

---

## Overview

- Connect to the broker WebSocket (ML-DSA-87 authentication)
- Run **Alice CGGMP** DKG / Refresh / Sign
- Forward MPC messages encrypted with ML-KEM-1024
- Persist shards locally (`-keysdir`)

> **Deployment**: the MPC interaction protocol uses ML-KEM-1024; **the broker and all nodes must run the same version**.

---

## Directory layout

```text
.
├── main.go              # Node entrypoint
├── config.go            # JSON config loading
├── entry.go             # Startup and keystore initialization
├── mpc_*.go             # Keygen / Sign protocol handlers
├── connect/             # WebSocket SDK configuration
├── dto/                 # WebSocket protocol DTOs shared with the broker
└── mpc/                 # CGGMP + HD + signature verification
```

---

## Build and run

### Requirements

- Go 1.26+

### Build

```bash
go build -o wallet-mpc-node .
```

### Run

Each node uses its own JSON config file (e.g. `cli_node0.json`) with the broker host, WebSocket address, ML-DSA credentials, and related settings:

```bash
./wallet-mpc-node -config=cli_node0.json
./wallet-mpc-node -config=cli_node0.json -keysdir=./data/shards
./wallet-mpc-node -config=cli_node0.json -logdir=./logs
```

Production TEE (private keys are not stored in JSON; override via env):

```bash
set MPC_NODE_CLIENT_PRK=<tee-unsealed>
set MPC_KEYSTORE_KEY=<tee-unsealed>
./wallet-mpc-node -config=cli_node0.json
```

---

## Configuration

| Item | Description |
|------|-------------|
| **cli_nodeN.json** | Broker host, WebSocket, ML-DSA auth, `shardKeysDir` |
| **-keysdir** | MPC shard storage directory (overrides JSON `shardKeysDir`; default `keys`) |
| **MPC_KEYSTORE_KEY** / **keystoreKey** | Shard encryption key (required; plaintext shards are not supported) |

---

## Dependencies

| Repository | Purpose |
|------------|---------|
| [github.com/getamis/alice](https://github.com/getamis/alice) | CGGMP threshold ECDSA |
| [github.com/godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | ML-KEM-1024 / ML-DSA-87 |
| [github.com/godaddy-x/freego](https://github.com/godaddy-x/freego) | WebSocket / utilities |
| [github.com/godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | HD derivation types |

---

## License

GPL-3.0
