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
├── mpc/
│   ├── alg_ecdsa/                   # CGGMP
│   ├── alg_ed25519/                 # FROST
│   ├── hd/                          # HD 派生
│   ├── ecdsa/, ed25519/             # 链上验签
├── build_release.bat, build_release.sh
```

## 构建与运行

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
| windows/amd64 | `output/wallet-mpc-node-windows-amd64.exe` |

手动示例（linux/amd64）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o output/wallet-mpc-node-linux-amd64 .
```

可选 [UPX](https://upx.github.io/) 压缩（`upx --best --lzma output/...`）可减小体积；部分杀毒软件可能误报。

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

## 配置说明

| 项 | 说明 |
|----|------|
| `cli_nodeN.json` | broker 域名、WebSocket、ML-DSA 认证、`shardKeysDir` |
| `-keysdir` | 分片目录（覆盖 JSON；默认 `keys`） |
| `MPC_KEYSTORE_KEY` / `keystoreKey` | 分片加密密钥（必填，不支持明文分片） |

## 依赖

| 仓库 | 用途 |
|------|------|
| [getamis/alice](https://github.com/getamis/alice) | CGGMP（ECDSA）· FROST（Ed25519） |
| [godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | ML-KEM-1024 · ML-DSA-87 |
| [godaddy-x/freego](https://github.com/godaddy-x/freego) | WebSocket / 工具 |
| [godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | HD 派生类型 |

## 许可证

GPL-3.0
