// Package alg_ed25519 基于 getamis/alice FROST 的 Ed25519 (t,n) 门限签名。
package alg_ed25519

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	ProtocolVersion = "frost-v1"
)

// KeyIDFromPubHex Ed25519 32 字节公钥 hex → KeyID。
func KeyIDFromPubHex(pubHex string) string {
	b, err := hex.DecodeString(pubHex)
	if err != nil || len(b) != 32 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
