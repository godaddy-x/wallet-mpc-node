# mpc 子模块

MPC 密码学与协调相关包。

| 包 | 说明 |
|----|------|
| **mpc/alg_ecdsa/** | Alice CGGMP：DKG、Refresh、Sign、FileKeyStore、SignMaterialPool（ECDSA secp256k1） |
| **mpc/alg_ed25519/** | Alice FROST：DKG、Sign、FileKeyStore（Ed25519） |
| **mpc/hd/** | 根公钥 HD 派生：walletID / accountID / address 公钥（ECDSA + Ed25519） |
| **mpc/ecdsa/** | 链上 ECDSA 验签 |
| **mpc/ed25519/** | 链上 Ed25519 验签与 FROST 签名编码 |

总览见 [docs/MPC_FLOW.md](../docs/MPC_FLOW.md)。
