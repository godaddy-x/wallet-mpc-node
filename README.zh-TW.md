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
├── mpc/
│   ├── alg_ecdsa/                   # CGGMP
│   ├── alg_ed25519/                 # FROST
│   ├── hd/                          # HD 衍生
│   ├── ecdsa/, ed25519/             # 鏈上驗簽
├── build_release.bat, build_release.sh
```

## 建置與執行

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

可選 [UPX](https://upx.github.io/) 壓縮（`upx --best --lzma output/...`）可縮小體積；部分防毒軟體可能誤報。

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

| 項 | 說明 |
|----|------|
| `cli_nodeN.json` | broker 網域、WebSocket、ML-DSA 認證、`shardKeysDir` |
| `-keysdir` | 分片目錄（覆寫 JSON；預設 `keys`） |
| `MPC_KEYSTORE_KEY` / `keystoreKey` | 分片加密金鑰（必填，不支援明文分片） |

## 相依套件

| 儲存庫 | 用途 |
|--------|------|
| [getamis/alice](https://github.com/getamis/alice) | CGGMP（ECDSA）· FROST（Ed25519） |
| [godaddy-x/eccrypto](https://github.com/godaddy-x/eccrypto) | ML-KEM-1024 · ML-DSA-87 |
| [godaddy-x/freego](https://github.com/godaddy-x/freego) | WebSocket / 工具 |
| [godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter) | HD 衍生類型 |

## 授權條款

GPL-3.0
