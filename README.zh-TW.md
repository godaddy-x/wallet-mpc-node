# wallet-mpc-node

<p align="center">
  <a href="./README.md">English</a>
  ·
  <a href="./README.zh.md">简体中文</a>
  ·
  <a href="./README.zh-TW.md"><strong>繁體中文</strong></a>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

MPC TSS 節點程序：連線 [wallet-mpc-broker](https://github.com/godaddy-x/wallet-mpc-broker) WebSocket，參與 CGGMP 門檻金鑰產生與簽章；MPC 協定訊息以 ML-KEM-1024 加密，分片本機落盤。

| | |
|---|---|
| **模組路徑** | `github.com/godaddy-x/wallet-mpc-node` |
| **配套儲存庫** | [wallet-mpc-broker](https://github.com/godaddy-x/wallet-mpc-broker)（協調器 / CLI） |

---

## 概述

- 連線 Broker WebSocket（ML-DSA-87 認證）
- 執行 **Alice CGGMP** DKG / Refresh / Sign
- MPC 訊息以 ML-KEM-1024 加密轉發
- shard 本機落盤（`-keysdir`）

> **部署**：MPC 互動協定使用 ML-KEM-1024，**broker 與全部 node 須同版本**。

---

## 目錄結構

```text
.
├── main.go              # 節點入口
├── config.go            # JSON 設定載入
├── entry.go             # 啟動與 keystore 初始化
├── mpc_*.go             # Keygen / Sign 協定處理
├── connect/             # WebSocket SDK 設定
├── dto/                 # 與 broker 的 WebSocket 協定 DTO
└── mpc/                 # CGGMP + HD + 驗簽
```

---

## 建置與執行

### 環境需求

- Go 1.26+

### 建置

```bash
go build -o wallet-mpc-node .
```

### 執行

每個節點使用獨立 JSON 設定（如 `cli_node0.json`），包含 broker 網域、WebSocket 位址、ML-DSA 認證等：

```bash
./wallet-mpc-node -config=cli_node0.json
./wallet-mpc-node -config=cli_node0.json -keysdir=./data/shards
./wallet-mpc-node -config=cli_node0.json -logdir=./logs
```

生產 TEE（私鑰不寫入 JSON，由 env 覆寫）：

```bash
set MPC_NODE_CLIENT_PRK=<tee-unsealed>
set MPC_KEYSTORE_KEY=<tee-unsealed>
./wallet-mpc-node -config=cli_node0.json
```

---

## 設定說明

| 項 | 說明 |
|----|------|
| **cli_nodeN.json** | broker 網域、WebSocket、ML-DSA 認證、`shardKeysDir` |
| **-keysdir** | MPC 分片落盤目錄（覆寫 json `shardKeysDir`；預設 `keys`） |
| **MPC_KEYSTORE_KEY** / **keystoreKey** | 分片加密金鑰（必填，不支援明文分片） |

---

## 相依套件

| 儲存庫 | 用途 |
|--------|------|
| [github.com/getamis/alice](https://github.com/getamis/alice) | CGGMP 門檻 ECDSA |
| [github.com/godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | ML-KEM-1024 / ML-DSA-87 |
| [github.com/godaddy-x/freego](https://github.com/godaddy-x/freego) | WebSocket / 工具 |
| [github.com/godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | HD 衍生類型 |

---

## 授權條款

GPL-3.0
