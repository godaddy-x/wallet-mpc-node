// Package ed25519 提供链上 Ed25519 验签与 FROST 签名编码。
package ed25519

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
)

// EncodeEd25519PubKey 将 Alice ECPoint 编码为标准 32 字节 Ed25519 公钥。
func EncodeEd25519PubKey(pt *ecpointgrouplaw.ECPoint) ([]byte, error) {
	if pt == nil {
		return nil, fmt.Errorf("ed25519: nil point")
	}
	if pt.IsIdentity() {
		return nil, fmt.Errorf("ed25519: identity point")
	}
	pub := edwards.NewPublicKey(edwards.Edwards(), pt.GetX(), pt.GetY())
	out := pub.SerializeCompressed()
	if len(out) != 32 {
		return nil, fmt.Errorf("ed25519: invalid compressed pubkey length %d", len(out))
	}
	return out, nil
}

// EncodeSignature 将 FROST R,S 编码为 64 字节 Ed25519 签名（与 Alice FROST / decred edwards 一致）。
func EncodeSignature(rPt *ecpointgrouplaw.ECPoint, s *big.Int) ([]byte, error) {
	if rPt == nil || s == nil {
		return nil, fmt.Errorf("ed25519: nil R or S")
	}
	rEnc := edwards.BigIntPointToEncodedBytes(rPt.GetX(), rPt.GetY())
	if rEnc == nil {
		return nil, fmt.Errorf("ed25519: encode R point")
	}
	sEnc := edwards.BigIntToEncodedBytes(s)
	sig := make([]byte, 64)
	copy(sig[:32], rEnc[:])
	copy(sig[32:], sEnc[:])
	return sig, nil
}

// VerifySignatureHex 验签：32 字节公钥 hex + 消息 hex + 64 字节签名 hex。
func VerifySignatureHex(pubHex, msgHex, sigHex string) (bool, error) {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return false, fmt.Errorf("decode pubHex: %w", err)
	}
	if len(pub) != 32 {
		return false, fmt.Errorf("pubHex must be 32 bytes")
	}
	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		return false, fmt.Errorf("decode msgHex: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("decode sigHex: %w", err)
	}
	if len(sig) != 64 {
		return false, fmt.Errorf("sigHex must be 64 bytes")
	}
	x, y, err := XYFromPubKeyBytes(pub)
	if err != nil {
		return false, err
	}
	edPub := edwards.NewPublicKey(edwards.Edwards(), x, y)
	var rBytes [32]byte
	copy(rBytes[:], sig[:32])
	r := edwards.EncodedBytesToBigInt(&rBytes)
	var sBytes [32]byte
	copy(sBytes[:], sig[32:])
	s := edwards.EncodedBytesToBigInt(&sBytes)
	return edwards.Verify(edPub, msg, r, s), nil
}

// XYFromPubKeyBytes 解码 32 字节 Ed25519 公钥为 big.Int 坐标（与 decred SerializeCompressed 互逆）。
func XYFromPubKeyBytes(pub []byte) (*big.Int, *big.Int, error) {
	if len(pub) != 32 {
		return nil, nil, fmt.Errorf("ed25519: invalid pubkey length")
	}
	key, err := edwards.ParsePubKey(edwards.Edwards(), pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519: parse pubkey: %w", err)
	}
	return key.GetX(), key.GetY(), nil
}
