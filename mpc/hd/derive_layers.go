package hd

import (
	"fmt"

	"github.com/godaddy-x/wallet-adapter/chain"
)

// MPCHDWallet 钱包层：MPC 根公钥 → KeyID → WalletID。
type MPCHDWallet struct {
	KeyID      string // SHA256(rootPub X||Y) hex，DKG 内部标识
	WalletID   string // Base58Check(SHA256→RIPEMD160(keyID))，业务 walletID
	RootPubHex string // 65 字节非压缩公钥 hex
}

// MPCHDAccount 账户层：根公钥 + accountIndex → AccountID + 账户公钥。
type MPCHDAccount struct {
	MPCHDWallet
	AccountIndex  uint32
	AccountID     string // Base58Check(账户子公钥)
	AccountPubHex string
	HDPath        string // m/0/{accountIndex}
}

// MPCHDAddress 地址层：根公钥 + 完整路径 → AddressPubHex（链地址由 adapter/scanner 编码）。
type MPCHDAddress struct {
	MPCHDAccount
	Change        uint32
	AddressIndex  uint32
	AddressPubHex string
	HDPath        string // m/0/{account}/{change}/{address}
}

// WalletIDFromKeyID KeyID → WalletID（与 keygen 落盘一致）。
func WalletIDFromKeyID(keyID string) string {
	if keyID == "" {
		return ""
	}
	return chain.ComputeKeyID([]byte(keyID))
}

// KeyIDFromRootPubHex 根公钥 hex → KeyID。
func KeyIDFromRootPubHex(rootPubHex string) (string, error) {
	root, err := RootPubHexToECDSA(rootPubHex)
	if err != nil {
		return "", err
	}
	keyID := KeyIDFromPubXY(root.X, root.Y)
	if keyID == "" {
		return "", fmt.Errorf("hd: empty keyID from root pub")
	}
	return keyID, nil
}

// AccountIDFromPubBytes 子公钥 65 字节 → AccountID（与 CreateAccount 一致）。
func AccountIDFromPubBytes(pubBytes []byte) string {
	if len(pubBytes) == 0 {
		return ""
	}
	return chain.ComputeKeyID(pubBytes)
}

// DeriveMPCHDWallet 第 1 层：仅派生 WalletID / KeyID。
func DeriveMPCHDWallet(rootPubHex string) (*MPCHDWallet, error) {
	keyID, err := KeyIDFromRootPubHex(rootPubHex)
	if err != nil {
		return nil, err
	}
	return &MPCHDWallet{
		KeyID:      keyID,
		WalletID:   WalletIDFromKeyID(keyID),
		RootPubHex: rootPubHex,
	}, nil
}

// DeriveMPCHDAccount 第 2 层：账户派生 m/0/{accountIndex}。
func DeriveMPCHDAccount(rootPubHex, keyID string, accountIndex uint32) (*MPCHDAccount, error) {
	wallet, err := deriveWalletLayer(rootPubHex, keyID)
	if err != nil {
		return nil, err
	}
	root, err := RootPubHexToECDSA(wallet.RootPubHex)
	if err != nil {
		return nil, err
	}
	_, child, err := DeriveChildPubFromPath(root, ChainCodeFromKeyID(wallet.KeyID), PathFromAccountIndex(accountIndex))
	if err != nil {
		return nil, err
	}
	pubHex, pubBytes := PubKeyToHex(child)
	return &MPCHDAccount{
		MPCHDWallet:   *wallet,
		AccountIndex:  accountIndex,
		AccountID:     AccountIDFromPubBytes(pubBytes),
		AccountPubHex: pubHex,
		HDPath:        FormatAccountHDPath(accountIndex),
	}, nil
}

// DeriveMPCHDAddress 第 3 层：地址派生 m/0/{account}/{change}/{address}。
func DeriveMPCHDAddress(rootPubHex, keyID string, path MPCHDPath) (*MPCHDAddress, error) {
	account, err := DeriveMPCHDAccount(rootPubHex, keyID, path.AccountIndex)
	if err != nil {
		return nil, err
	}
	root, err := RootPubHexToECDSA(account.RootPubHex)
	if err != nil {
		return nil, err
	}
	derivPath := PathFromAccountAndAddress(path.AccountIndex, path.Change, path.AddressIndex)
	_, child, err := DeriveChildPubFromPath(root, ChainCodeFromKeyID(account.KeyID), derivPath)
	if err != nil {
		return nil, err
	}
	pubHex, _ := PubKeyToHex(child)
	return &MPCHDAddress{
		MPCHDAccount:  *account,
		Change:        path.Change,
		AddressIndex:  path.AddressIndex,
		AddressPubHex: pubHex,
		HDPath:        path.FormatAddress(),
	}, nil
}

func deriveWalletLayer(rootPubHex, keyID string) (*MPCHDWallet, error) {
	if keyID != "" {
		if rootPubHex == "" {
			return nil, fmt.Errorf("hd: rootPubHex required when keyID is set")
		}
		expected, err := KeyIDFromRootPubHex(rootPubHex)
		if err != nil {
			return nil, err
		}
		if keyID != expected {
			return nil, fmt.Errorf("hd: keyID mismatch with rootPubHex")
		}
		return &MPCHDWallet{
			KeyID:      keyID,
			WalletID:   WalletIDFromKeyID(keyID),
			RootPubHex: rootPubHex,
		}, nil
	}
	return DeriveMPCHDWallet(rootPubHex)
}
