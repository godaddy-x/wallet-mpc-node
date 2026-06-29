# wallet-mpc-node

<p align="center">
  <a href="./README.md">English</a>
  ·
  <a href="./README.zh.md"><strong>简体中文</strong></a>
  ·
  <a href="./README.zh-TW.md">繁體中文</a>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

MPC TSS 节点进程：连接 [wallet-mpc-broker](https://github.com/godaddy-x/wallet-mpc-broker) WebSocket，参与 CGGMP 门限密钥生成与签名；MPC 协议消息 ML-KEM-1024 加密，分片本地落盘。

| | |
|---|---|
| **模块路径** | `github.com/godaddy-x/wallet-mpc-node` |
| **配套仓库** | [wallet-mpc-broker](https://github.com/godaddy-x/wallet-mpc-broker)（协调器 / CLI） |

---

## 概述

- 连接 Broker WebSocket（ML-DSA-87 认证）
- 运行 **Alice CGGMP** DKG / Refresh / Sign
- MPC 消息 ML-KEM-1024 加密转发
- shard 本地落盘（`-keysdir`）

> **部署**：MPC 交互协议使用 ML-KEM-1024，**broker 与全部 node 须同版本**。

---

## 目录结构

```text
.
├── main.go              # 节点入口
├── config.go            # JSON 配置加载
├── entry.go             # 启动与 keystore 初始化
├── mpc_*.go             # Keygen / Sign 协议处理
├── connect/             # WebSocket SDK 配置
├── dto/                 # 与 broker 的 WebSocket 协议 DTO
└── mpc/                 # CGGMP + HD + 验签
```

---

## 构建与运行

### 环境要求

- Go 1.26+

### 构建

```bash
go build -o wallet-mpc-node .
```

### 运行

每个节点使用独立 JSON 配置（如 `cli_node0.json`），包含 broker 域名、WebSocket 地址、ML-DSA 认证等：

```bash
./wallet-mpc-node -config=cli_node0.json
./wallet-mpc-node -config=cli_node0.json -keysdir=./data/shards
./wallet-mpc-node -config=cli_node0.json -logdir=./logs
```

生产 TEE（私钥不进 JSON，由 env 覆盖）：

```bash
set MPC_NODE_CLIENT_PRK=<tee-unsealed>
set MPC_KEYSTORE_KEY=<tee-unsealed>
./wallet-mpc-node -config=cli_node0.json
```

---

## 配置说明

| 项 | 说明 |
|----|------|
| **cli_nodeN.json** | broker 域名、WebSocket、ML-DSA 认证、`shardKeysDir` |
| **-keysdir** | MPC 分片落盘目录（覆盖 json `shardKeysDir`；默认 `keys`） |
| **MPC_KEYSTORE_KEY** / **keystoreKey** | 分片加密密钥（必填，不支持明文分片） |

---

## 依赖

| 仓库 | 用途 |
|------|------|
| [github.com/getamis/alice](https://github.com/getamis/alice) | CGGMP 门限 ECDSA |
| [github.com/godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | ML-KEM-1024 / ML-DSA-87 |
| [github.com/godaddy-x/freego](https://github.com/godaddy-x/freego) | WebSocket / 工具 |
| [github.com/godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | HD 派生类型 |

---

## 许可证

GPL-3.0
