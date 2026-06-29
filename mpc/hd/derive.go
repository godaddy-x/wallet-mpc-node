// Package hd 提供 MPC 钱包的公钥 HD 派生（无 seed、仅非硬化路径），与 TSS 库无关。
package hd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ChainCodeFromKeyID 用 KeyID 生成 32 字节 chainCode。
func ChainCodeFromKeyID(keyID string) []byte {
	h := sha256.Sum256([]byte(keyID))
	return h[:]
}

// PathFromAccountIndex 账户层路径。
func PathFromAccountIndex(accountIndex uint32) []uint32 {
	return []uint32{accountIndex}
}

// PathFromAccountAndAddress 账户 + 地址两级路径（全非硬化）。
func PathFromAccountAndAddress(accountIndex, change, addrIndex uint32) []uint32 {
	return []uint32{accountIndex, change, addrIndex}
}

// Pad32 填充或截断为 32 字节。
func Pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// PubKeyToHex 65 字节非压缩公钥 hex。
func PubKeyToHex(pub *ecdsa.PublicKey) (string, []byte) {
	if pub == nil {
		return "", nil
	}
	b := make([]byte, 65)
	b[0] = 0x04
	copy(b[1:33], Pad32(pub.X.Bytes()))
	copy(b[33:65], Pad32(pub.Y.Bytes()))
	return hex.EncodeToString(b), b
}

// KeyIDFromPubXY 从根公钥坐标算 KeyID。
func KeyIDFromPubXY(pubX, pubY *big.Int) string {
	if pubX == nil || pubY == nil {
		return ""
	}
	h := sha256.New()
	h.Write(Pad32(pubX.Bytes()))
	h.Write(Pad32(pubY.Bytes()))
	return hex.EncodeToString(h.Sum(nil))
}

func curveOrder() *big.Int {
	return secp256k1.S256().N
}

func compressedPub(pub *ecdsa.PublicKey) []byte {
	b := make([]byte, 33)
	if pub.Y.Bit(0) == 0 {
		b[0] = 0x02
	} else {
		b[0] = 0x03
	}
	copy(b[1:], Pad32(pub.X.Bytes()))
	return b
}

func pubFromXY(x, y *big.Int) (*ecdsa.PublicKey, error) {
	if x == nil || y == nil {
		return nil, fmt.Errorf("hd: nil pubkey coordinates")
	}
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     new(big.Int).Set(x),
		Y:     new(big.Int).Set(y),
	}, nil
}

func addPubScalar(pub *ecdsa.PublicKey, k *big.Int) (*ecdsa.PublicKey, error) {
	if pub == nil || k == nil {
		return nil, fmt.Errorf("hd: nil pub or scalar")
	}
	kG := scalarBaseMult(k)
	x, y := secp256k1.S256().Add(pub.X, pub.Y, kG.X, kG.Y)
	return pubFromXY(x, y)
}

func scalarBaseMult(k *big.Int) *ecdsa.PublicKey {
	x, y := secp256k1.S256().ScalarBaseMult(k.Bytes())
	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
}

func ser32(i uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(i >> 24)
	b[1] = byte(i >> 16)
	b[2] = byte(i >> 8)
	b[3] = byte(i)
	return b
}

// DeriveChildPubFromPath 非硬化 BIP32 风格派生；返回累计 delta 与子公钥。
func DeriveChildPubFromPath(rootPub *ecdsa.PublicKey, chainCode []byte, path []uint32) (keyDerivationDelta *big.Int, childPub *ecdsa.PublicKey, err error) {
	if rootPub == nil || len(chainCode) < 32 {
		return nil, nil, fmt.Errorf("hd: rootPub and 32-byte chainCode required")
	}
	if len(path) == 0 {
		return nil, nil, fmt.Errorf("hd: empty path")
	}
	n := curveOrder()
	delta := big.NewInt(0)
	pub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     new(big.Int).Set(rootPub.X),
		Y:     new(big.Int).Set(rootPub.Y),
	}
	cc := make([]byte, 32)
	copy(cc, chainCode)

	for _, index := range path {
		if index >= 0x80000000 {
			return nil, nil, fmt.Errorf("hd: hardened index not supported: %d", index)
		}
		mac := hmac.New(sha512.New, cc)
		_, _ = mac.Write(compressedPub(pub))
		_, _ = mac.Write(ser32(index))
		I := mac.Sum(nil)
		il := new(big.Int).SetBytes(Pad32(I[:32]))
		if il.Cmp(n) >= 0 {
			return nil, nil, fmt.Errorf("hd: invalid child derivation il")
		}
		delta.Add(delta, il)
		delta.Mod(delta, n)
		pub, err = addPubScalar(pub, il)
		if err != nil {
			return nil, nil, err
		}
		copy(cc, I[32:])
	}
	return delta, pub, nil
}

// RootPubHexToECDSA 解析 04||X||Y。
func RootPubHexToECDSA(rootPubHex string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(rootPubHex)
	if err != nil {
		return nil, err
	}
	if len(b) != 65 || b[0] != 0x04 {
		return nil, fmt.Errorf("hd: invalid rootPubHex")
	}
	return pubFromXY(
		new(big.Int).SetBytes(b[1:33]),
		new(big.Int).SetBytes(b[33:65]),
	)
}

// DeriveMPCAccountFromRootPubHex AccountID + 公钥 hex（账户层 m/0/{account}）。
func DeriveMPCAccountFromRootPubHex(rootPubHex, keyID string, index uint32) (accountID, pubHex string, err error) {
	acc, err := DeriveMPCHDAccount(rootPubHex, keyID, index)
	if err != nil {
		return "", "", err
	}
	return acc.AccountID, acc.AccountPubHex, nil
}

// DeriveMPCAddressPubFromRootPubHex 地址层子公钥 hex（m/0/{account}/{change}/{address}）。
func DeriveMPCAddressPubFromRootPubHex(rootPubHex, keyID string, accountIndex, change, addrIndex uint32) (pubHex string, err error) {
	addr, err := DeriveMPCHDAddress(rootPubHex, keyID, NewMPCHDPath(accountIndex, change, addrIndex))
	if err != nil {
		return "", err
	}
	return addr.AddressPubHex, nil
}

// MessageHashFromTxHash hex → *big.Int。
func MessageHashFromTxHash(txHashHex string) (*big.Int, error) {
	b, err := hex.DecodeString(txHashHex)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("hd: tx hash must be 32 bytes")
	}
	return new(big.Int).SetBytes(b), nil
}

// Ensure secp256k1 curve type alias for external use.
func S256() elliptic.Curve {
	return secp256k1.S256()
}
