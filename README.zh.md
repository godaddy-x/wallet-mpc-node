# wallet-mpc-node

<p align="center">
  <a href="./README.md">English</a>
  ·
  <a href="./README.zh.md"><strong>简体中文</strong></a>
  ·
  <a href="./README.zh-TW.md">繁體中文</a>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

开源 **MPC 签名节点**（GPL-3.0）。连接 **wallet-mpc-broker**（闭源），在本地执行门限 Keygen / Refresh / Sign（**ECDSA · CGGMP** 或 **Ed25519 · FROST**），MPC 协议消息 ML-KEM-1024 加密，分片加密落盘。

> [!CAUTION]
> **切勿使用第三方、Fork 或未经验证的源码编译或运行本节点。** 本进程持有 MPC 密钥分片，被篡改的构建可能导致分片泄露或破坏门限安全。**broker 为闭源，仅使用官方发行包，勿使用来路不明的 broker。**

## 节点与 broker

| | **wallet-mpc-node**（本仓库） | **wallet-mpc-broker** |
|---|---|---|
| **角色** | 签名节点，持有并运算分片 | 协调器 / CLI，编排 Keygen / Sign |
| **许可** | GPL-3.0 · **开源** | 专有 · **闭源** |
| **构建** | 本仓库 `go build` | 仅官方发行包 |

## 签名算法

Keygen / Sign 由 broker 会话 DTO 的 **`algorithm`** 字段路由（`ecdsa` | `ed25519`）：

| 标识 | 链上算法 | 门限协议 | 代码 |
|------|----------|----------|------|
| `ecdsa` | secp256k1 ECDSA | CGGMP | `mpc/alg_ecdsa/` |
| `ed25519` | Ed25519（EdDSA） | FROST | `mpc/alg_ed25519/` |

- 根公钥 hex 可反推算法：65 字节 uncompressed → `ecdsa`；32 字节 → `ed25519`。
- HD 派生：`mpc/hd/`，两种曲线均支持。
- 钱包 `algorithm` 由 broker KeyMeta 下发，节点本地不自行选择。
- ML-KEM 端到端加密对两种协议栈均生效；broker 无法解密 WireBytes。

> **部署：** broker 与全部 node 须 **同版本**（ML-KEM-1024 线协议）。

## 目录结构

```text
.
├── main.go, config.go, entry.go
├── mpc_keygen.go, mpc_sign.go       # 按 algorithm 路由
├── mpc_ecdsa.go, mpc_ed25519.go     # CGGMP / FROST 流程
├── connect/                         # WebSocket SDK
├── dto/                             # 协议 DTO（broker ↔ node）
├── examples/                        # cli_node*.example.json
├── pqc-keypair.md                   # PQC（ML-DSA-87）密钥对生成与安全说明
├── mpc/
│   ├── alg_ecdsa/                   # CGGMP
│   ├── alg_ed25519/                 # FROST
│   ├── hd/                          # HD 派生
│   ├── ecdsa/, ed25519/             # 链上验签
├── build_release.bat, build_release.sh
└── .github/workflows/release.yml   # tag → Release + SHA256SUMS
```

## 官方发行

预编译二进制 **仅** 从 **[GitHub Releases](https://github.com/godaddy-x/wallet-mpc-node/releases)** 下载。推送 `v*` 标签会触发 [`.github/workflows/release.yml`](.github/workflows/release.yml) 交叉编译并发布：

| 产物 | 平台 |
|------|------|
| `wallet-mpc-node-linux-amd64` | Linux x86_64 |
| `wallet-mpc-node-linux-arm64` | Linux ARM64 |
| `wallet-mpc-node-darwin-amd64` | macOS Intel（x86_64） |
| `wallet-mpc-node-darwin-arm64` | macOS Apple Silicon（ARM64） |
| `wallet-mpc-node-windows-amd64.exe` | Windows x86_64 |
| `SHA256SUMS` | 以上二进制 SHA-256 校验和 |

**部署前校验：**

```bash
# Linux / macOS — 在下载目录执行（仅下载单平台时可忽略缺失文件）
sha256sum -c --ignore-missing SHA256SUMS
```

```powershell
# Windows — 与 SHA256SUMS 中 wallet-mpc-node-windows-amd64.exe 一行比对
Get-FileHash .\wallet-mpc-node-windows-amd64.exe -Algorithm SHA256
```

维护者发布版本：

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 构建与运行

> ℹ️ **生产部署**请使用上方 [官方发行](#官方发行) 中的预编译二进制；以下内容仅供开发调试。

**环境要求：** Go 1.26+

**快速构建：**

```bash
go build -o wallet-mpc-node .
```

**交叉编译**（静态链接 `CGO_ENABLED=0`，产物在 `output/`）：

```bat
build_release.bat          REM Windows
```

```bash
chmod +x build_release.sh && ./build_release.sh   # Linux / macOS
```

| 平台 | 输出 |
|------|------|
| linux/amd64 | `output/wallet-mpc-node-linux-amd64` |
| linux/arm64 | `output/wallet-mpc-node-linux-arm64` |
| darwin/amd64 | `output/wallet-mpc-node-darwin-amd64` |
| darwin/arm64 | `output/wallet-mpc-node-darwin-arm64` |
| windows/amd64 | `output/wallet-mpc-node-windows-amd64.exe` |

手动示例（linux/amd64）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o output/wallet-mpc-node-linux-amd64 .
```

**运行**（每节点一份配置，如 `cli_node0.json`）：

```bash
./wallet-mpc-node -config=cli_node0.json
./wallet-mpc-node -config=cli_node0.json -keysdir=./data/shards -logdir=./logs
```

生产 TEE（密钥通过 env 注入，不写进 JSON）：

```bash
export MPC_NODE_CLIENT_PRK=<tee-unsealed>   # Windows cmd: set MPC_NODE_CLIENT_PRK=...
export MPC_KEYSTORE_KEY=<tee-unsealed>
./wallet-mpc-node -config=cli_node0.json
```

## PQC 密钥对生成

在填写配置中的 `clientPrk` 之前，需为节点生成 **PQC 身份密钥对**（ML-DSA-87）。**完整流程、落盘格式与安全要点见：** [`pqc-keypair.md`](pqc-keypair.md)（英文）。

```bash
# 开发环境（明文 private.key，勿用于生产）
./wallet-mpc-node -genkey

# 生产环境（加密 private.key）
export MPC_PLAN2_WRAP_KEY='<强口令>'
./wallet-mpc-node -genkey -enc -outdir /secure/path/node0-pqc
```

`private.key` 对应 `clientPrk` 或 `MPC_NODE_CLIENT_PRK`；`public.pem` 需登记到 broker 的 `nodeBindings`。

## 配置说明

复制 [`examples/cli_node0.example.json`](examples/cli_node0.example.json) 为 `cli_node0.json`（已 gitignore），填入 broker **`nodeBindings`** 中的值。生产 TEE 可在 JSON 中省略 `clientPrk` / `keystoreKey`，改由 env 注入 — 见 [`examples/cli_node.prod.example.json`](examples/cli_node.prod.example.json)。

| 字段 | 必填 | 说明 |
|------|------|------|
| `domain` | 是 | broker 节点 WebSocket 地址（`host:port`，broker `port+100`） |
| `source` | 是 | 节点 ID（`node0`、`node1`…），须与 broker `nodeBindings` 一致 |
| `keyPath` | 是 | 登录后 WS 路由（默认 `/ws/key`） |
| `loginPath` | 是 | PQC 身份登录路由（默认 `/ws/login`） |
| `clientNo` | 是 | broker `nodeBindings` 中分配的 clientNo |
| `serverPub` | 是 | broker ML-DSA-87 公钥 |
| `clientPrk` | 是* | 节点 ML-DSA-87 私钥（*生产：`MPC_NODE_CLIENT_PRK` env） |
| `broadcastKey` | 是 | Push 签名校验 key（hex），须与 broker 一致 |
| `keystoreKey` | 是* | 分片落盘加密密钥（*生产：`MPC_KEYSTORE_KEY` env） |
| `shardKeysDir` | 否 | 分片目录（默认 `keys`；可被 `-keysdir` 覆盖） |

<details>
<summary><code>cli_node0.json</code> — 最小示例</summary>

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

## 依赖

以下为 `go.mod` 直接依赖。所列许可证均**与 GPL-3.0 兼容**。

| 仓库 | 许可证 | 用途 |
|------|--------|------|
| [getamis/alice](https://github.com/getamis/alice) | Apache-2.0 | CGGMP（ECDSA）· FROST（Ed25519） |
| [godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | MIT | ML-KEM-1024 · ML-DSA-87 |
| [godaddy-x/freego](https://github.com/godaddy-x/freego) | MIT | WebSocket / 工具 |
| [godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | MIT | HD 派生类型 |

## 许可证

GPL-3.0
