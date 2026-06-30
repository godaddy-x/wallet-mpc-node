# wallet-mpc-node

<p align="center">
  <a href="./README.md">English</a>
  ·
  <a href="./README.zh.md">简体中文</a>
  ·
  <a href="./README.zh-TW.md"><strong>繁體中文</strong></a>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

開源 **MPC 簽章節點**（GPL-3.0）。連線 **wallet-mpc-broker**（閉源），於本機執行門檻 Keygen / Refresh / Sign（**ECDSA · CGGMP** 或 **Ed25519 · FROST**），MPC 協定訊息以 ML-KEM-1024 加密，分片加密落盤。

> [!CAUTION]
> **切勿使用第三方、Fork 或未經驗證的原始碼編譯或執行本節點。** 本程序持有 MPC 金鑰分片，遭篡改的建置可能導致分片外洩或破壞門檻安全。**broker 為閉源，僅使用官方發行套件，勿使用來路不明的 broker。**

## 節點與 broker

| | **wallet-mpc-node**（本儲存庫） | **wallet-mpc-broker** |
|---|---|---|
| **角色** | 簽章節點，持有並運算分片 | 協調器 / CLI，編排 Keygen / Sign |
| **授權** | GPL-3.0 · **開源** | 專有 · **閉源** |
| **建置** | 本儲存庫 `go build` | 僅官方發行套件 |

## 簽章演算法

Keygen / Sign 由 broker 工作階段 DTO 的 **`algorithm`** 欄位路由（`ecdsa` | `ed25519`）：

| 識別 | 鏈上演算法 | 門檻協定 | 程式碼 |
|------|------------|----------|--------|
| `ecdsa` | secp256k1 ECDSA | CGGMP | `mpc/alg_ecdsa/` |
| `ed25519` | Ed25519（EdDSA） | FROST | `mpc/alg_ed25519/` |

- 根公鑰 hex 可反推演算法：65 位元組 uncompressed → `ecdsa`；32 位元組 → `ed25519`。
- HD 衍生：`mpc/hd/`，兩種曲線均支援。
- 錢包 `algorithm` 由 broker KeyMeta 下發，節點本機不自行選擇。
- ML-KEM 端到端加密對兩種協定堆疊均生效；broker 無法解密 WireBytes。

> **部署：** broker 與全部 node 須 **同版本**（ML-KEM-1024 線協定）。

## 目錄結構

```text
.
├── main.go, config.go, entry.go
├── mpc_keygen.go, mpc_sign.go       # 依 algorithm 路由
├── mpc_ecdsa.go, mpc_ed25519.go     # CGGMP / FROST 流程
├── connect/                         # WebSocket SDK
├── dto/                             # 協定 DTO（broker ↔ node）
├── examples/                        # cli_node*.example.json
├── mpc/
│   ├── alg_ecdsa/                   # CGGMP
│   ├── alg_ed25519/                 # FROST
│   ├── hd/                          # HD 衍生
│   ├── ecdsa/, ed25519/             # 鏈上驗簽
├── build_release.bat, build_release.sh
└── .github/workflows/release.yml   # tag → Release + SHA256SUMS
```

## 官方發行

預編譯二進位檔 **僅** 從 **[GitHub Releases](https://github.com/godaddy-x/wallet-mpc-node/releases)** 下載。推送 `v*` 標籤會觸發 [`.github/workflows/release.yml`](.github/workflows/release.yml) 交叉編譯並發佈：

| 產物 | 平台 |
|------|------|
| `wallet-mpc-node-linux-amd64` | Linux x86_64 |
| `wallet-mpc-node-linux-arm64` | Linux ARM64 |
| `wallet-mpc-node-windows-amd64.exe` | Windows x86_64 |
| `SHA256SUMS` | 以上二進位檔 SHA-256 校驗和 |

**部署前校驗：**

```bash
# Linux / macOS — 在下載目錄執行（僅下載單平台時可忽略缺失檔案）
sha256sum -c --ignore-missing SHA256SUMS
```

```powershell
# Windows — 與 SHA256SUMS 中 wallet-mpc-node-windows-amd64.exe 一行比對
Get-FileHash .\wallet-mpc-node-windows-amd64.exe -Algorithm SHA256
```

維護者發佈版本：

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 建置與執行

> ℹ️ **生產部署**請使用上方 [官方發行](#官方發行) 的預編譯二進位檔；以下內容僅供開發除錯。

**環境需求：** Go 1.26+

**快速建置：**

```bash
go build -o wallet-mpc-node .
```

**交叉編譯**（靜態連結 `CGO_ENABLED=0`，產物在 `output/`）：

```bat
build_release.bat          REM Windows
```

```bash
chmod +x build_release.sh && ./build_release.sh   # Linux / macOS
```

| 平台 | 輸出 |
|------|------|
| linux/amd64 | `output/wallet-mpc-node-linux-amd64` |
| linux/arm64 | `output/wallet-mpc-node-linux-arm64` |
| windows/amd64 | `output/wallet-mpc-node-windows-amd64.exe` |

手動範例（linux/amd64）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o output/wallet-mpc-node-linux-amd64 .
```

**執行**（每節點一份設定，如 `cli_node0.json`）：

```bash
./wallet-mpc-node -config=cli_node0.json
./wallet-mpc-node -config=cli_node0.json -keysdir=./data/shards -logdir=./logs
```

生產 TEE（金鑰經 env 注入，不寫入 JSON）：

```bash
export MPC_NODE_CLIENT_PRK=<tee-unsealed>   # Windows cmd: set MPC_NODE_CLIENT_PRK=...
export MPC_KEYSTORE_KEY=<tee-unsealed>
./wallet-mpc-node -config=cli_node0.json
```

## 設定說明

複製 [`examples/cli_node0.example.json`](examples/cli_node0.example.json) 為 `cli_node0.json`（已 gitignore），填入 broker **`nodeBindings`** 中的值。生產 TEE 可在 JSON 中省略 `clientPrk` / `keystoreKey`，改由 env 注入 — 見 [`examples/cli_node.prod.example.json`](examples/cli_node.prod.example.json)。

| 欄位 | 必填 | 說明 |
|------|------|------|
| `domain` | 是 | broker 節點 WebSocket 位址（`host:port`，broker `port+100`） |
| `source` | 是 | 節點 ID（`node0`、`node1`…），須與 broker `nodeBindings` 一致 |
| `keyPath` | 是 | 登入後 WS 路由（預設 `/ws/key`） |
| `loginPath` | 是 | Plan2 登入路由（預設 `/ws/login`） |
| `clientNo` | 是 | broker `nodeBindings` 中的 Plan2 clientNo |
| `serverPub` | 是 | broker ML-DSA-87 公鑰 |
| `clientPrk` | 是* | 節點 ML-DSA-87 私鑰（*生產：`MPC_NODE_CLIENT_PRK` env） |
| `broadcastKey` | 是 | Push 簽章驗證 key（hex），須與 broker 一致 |
| `keystoreKey` | 是* | 分片落盤加密金鑰（*生產：`MPC_KEYSTORE_KEY` env） |
| `shardKeysDir` | 否 | 分片目錄（預設 `keys`；可被 `-keysdir` 覆寫） |

<details>
<summary><code>cli_node0.json</code> — 最小範例</summary>

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

## 相依套件

以下為 `go.mod` 直接相依。所列授權條款均**與 GPL-3.0 相容**。

| 儲存庫 | 授權 | 用途 |
|--------|------|------|
| [getamis/alice](https://github.com/getamis/alice) | Apache-2.0 | CGGMP（ECDSA）· FROST（Ed25519） |
| [godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | MIT | ML-KEM-1024 · ML-DSA-87 |
| [godaddy-x/freego](https://github.com/godaddy-x/freego) | MIT | WebSocket / 工具 |
| [godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | MIT | HD 衍生類型 |

## 授權條款

GPL-3.0
