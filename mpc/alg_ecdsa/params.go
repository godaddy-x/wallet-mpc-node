// Package alg_ecdsa ?? getamis/alice CGGMP ? ECDSA (t,n) ?????
package alg_ecdsa

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

const (
	ProtocolVersion = "cggmp-v1"
)

// KeyIDFromPubXY ? hd ????
func KeyIDFromPubXY(pubX, pubY *big.Int) string {
	if pubX == nil || pubY == nil {
		return ""
	}
	h := sha256.New()
	h.Write(pad32(pubX.Bytes()))
	h.Write(pad32(pubY.Bytes()))
	return hex.EncodeToString(h.Sum(nil))
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
