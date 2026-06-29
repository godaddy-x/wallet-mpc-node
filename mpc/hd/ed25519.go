package hd

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	mpced25519 "github.com/godaddy-x/wallet-mpc-node/mpc/ed25519"
)

func Ed25519Order() *big.Int {
	return elliptic.Ed25519().Params().N
}

func Ed25519XYFromPubHex(pubHex string) (*big.Int, *big.Int, error) {
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, nil, err
	}
	return mpced25519.XYFromPubKeyBytes(b)
}

// DeriveEd25519ChildPubFromPath 非硬化 BIP32 风格派生（Ed25519 曲线）；返回 delta 与 32 字节子公钥 hex。
func DeriveEd25519ChildPubFromPath(rootPubHex string, chainCode []byte, path []uint32) (keyDerivationDelta *big.Int, childPubHex string, err error) {
	if len(chainCode) < 32 {
		return nil, "", fmt.Errorf("hd/ed25519: 32-byte chainCode required")
	}
	if len(path) == 0 {
		return nil, "", fmt.Errorf("hd/ed25519: empty path")
	}
	rootBytes, err := hex.DecodeString(rootPubHex)
	if err != nil || len(rootBytes) != 32 {
		return nil, "", fmt.Errorf("hd/ed25519: rootPubHex must be 32 bytes hex")
	}
	x, y, err := mpced25519.XYFromPubKeyBytes(rootBytes)
	if err != nil {
		return nil, "", err
	}
	curve := elliptic.Ed25519()
	pub, err := ecpointgrouplaw.NewECPoint(curve, x, y)
	if err != nil {
		return nil, "", err
	}
	n := Ed25519Order()
	delta := big.NewInt(0)
	cc := make([]byte, 32)
	copy(cc, chainCode)

	for _, index := range path {
		if index >= 0x80000000 {
			return nil, "", fmt.Errorf("hd/ed25519: hardened index not supported: %d", index)
		}
		enc, err := mpced25519.EncodeEd25519PubKey(pub)
		if err != nil {
			return nil, "", err
		}
		mac := hmac.New(sha512.New, cc)
		_, _ = mac.Write(enc)
		_, _ = mac.Write(ser32(index))
		I := mac.Sum(nil)
		il := new(big.Int).SetBytes(Pad32(I[:32]))
		il.Mod(il, n)
		if il.Sign() == 0 {
			return nil, "", fmt.Errorf("hd/ed25519: invalid child derivation il")
		}
		delta.Add(delta, il)
		delta.Mod(delta, n)
		pub, err = addEd25519Scalar(pub, il)
		if err != nil {
			return nil, "", err
		}
		copy(cc, I[32:])
	}
	childBytes, err := mpced25519.EncodeEd25519PubKey(pub)
	if err != nil {
		return nil, "", err
	}
	return delta, hex.EncodeToString(childBytes), nil
}

func addEd25519Scalar(pub *ecpointgrouplaw.ECPoint, k *big.Int) (*ecpointgrouplaw.ECPoint, error) {
	if pub == nil || k == nil {
		return nil, fmt.Errorf("hd/ed25519: nil pub or scalar")
	}
	kG := ecpointgrouplaw.ScalarBaseMult(elliptic.Ed25519(), k)
	return pub.Add(kG)
}

// KeyIDFromEd25519PubHex SHA256(32B pubkey) hex。
func KeyIDFromEd25519PubHex(pubHex string) (string, error) {
	b, err := hex.DecodeString(pubHex)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("hd/ed25519: invalid pub hex")
	}
	return KeyIDFromEd25519PubBytes(b), nil
}

func KeyIDFromEd25519PubBytes(pub []byte) string {
	if len(pub) != 32 {
		return ""
	}
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// DeriveMPCHDAccountEd25519 账户层派生（Ed25519 根公钥 32B hex）。
func DeriveMPCHDAccountEd25519(rootPubHex, keyID string, accountIndex uint32) (*MPCHDAccount, error) {
	keyIDResolved := keyID
	if keyIDResolved == "" {
		var err error
		keyIDResolved, err = KeyIDFromEd25519PubHex(rootPubHex)
		if err != nil {
			return nil, err
		}
	} else if expected, err := KeyIDFromEd25519PubHex(rootPubHex); err == nil && keyIDResolved != expected {
		return nil, fmt.Errorf("hd/ed25519: keyID mismatch with rootPubHex")
	}
	wallet := &MPCHDWallet{
		KeyID:      keyIDResolved,
		WalletID:   WalletIDFromKeyID(keyIDResolved),
		RootPubHex: rootPubHex,
	}
	_, childHex, err := DeriveEd25519ChildPubFromPath(rootPubHex, ChainCodeFromKeyID(keyIDResolved), PathFromAccountIndex(accountIndex))
	if err != nil {
		return nil, err
	}
	childBytes, _ := hex.DecodeString(childHex)
	return &MPCHDAccount{
		MPCHDWallet:   *wallet,
		AccountIndex:  accountIndex,
		AccountID:     AccountIDFromPubBytes(childBytes),
		AccountPubHex: childHex,
		HDPath:        FormatAccountHDPath(accountIndex),
	}, nil
}

// DeriveMPCHDAddressEd25519 地址层派生。
func DeriveMPCHDAddressEd25519(rootPubHex, keyID string, path MPCHDPath) (*MPCHDAddress, error) {
	account, err := DeriveMPCHDAccountEd25519(rootPubHex, keyID, path.AccountIndex)
	if err != nil {
		return nil, err
	}
	derivPath := PathFromAccountAndAddress(path.AccountIndex, path.Change, path.AddressIndex)
	_, childHex, err := DeriveEd25519ChildPubFromPath(rootPubHex, ChainCodeFromKeyID(account.KeyID), derivPath)
	if err != nil {
		return nil, err
	}
	return &MPCHDAddress{
		MPCHDAccount:  *account,
		Change:        path.Change,
		AddressIndex:  path.AddressIndex,
		AddressPubHex: childHex,
		HDPath:        path.FormatAddress(),
	}, nil
}
