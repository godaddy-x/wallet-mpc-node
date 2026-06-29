// Package ecdsa 提供链上 ECDSA 验签工具（与 CGGMP 签名输出格式一致）。
package ecdsa

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

// VerifySignatureHex 使用 65 字节非压缩公钥与 64 字节 R||S 验签 32 字节消息哈希。
func VerifySignatureHex(pubHex, msgHex, sigHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return false, fmt.Errorf("decode pubHex: %w", err)
	}
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return false, fmt.Errorf("pubHex must be 65 bytes uncompressed (04||X||Y)")
	}
	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		return false, fmt.Errorf("decode msgHex: %w", err)
	}
	if len(msg) != 32 {
		return false, fmt.Errorf("msgHex must be 32 bytes")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("decode sigHex: %w", err)
	}
	if len(sig) != 64 {
		return false, fmt.Errorf("sigHex must be 64 bytes (R||S)")
	}

	curve := hd.S256()
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	if !curve.IsOnCurve(x, y) {
		return false, fmt.Errorf("pub key not on secp256k1 curve")
	}
	pub := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	return ecdsa.Verify(&pub, msg, r, s), nil
}
