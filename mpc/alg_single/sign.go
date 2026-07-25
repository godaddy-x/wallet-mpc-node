package alg_single

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

// KeygenECDSA 生成 secp256k1 根密钥对并落盘。
func KeygenECDSA(store *FileKeyStore, nodeID string) (keyID, rootPubHex string, err error) {
	if store == nil {
		return "", "", fmt.Errorf("single: nil keystore")
	}
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("single: generate ecdsa key: %w", err)
	}
	rootPubHex, _ = hd.PubKeyToHex(&priv.PublicKey)
	keyID = hd.KeyIDFromPubXY(priv.PublicKey.X, priv.PublicKey.Y)
	if keyID == "" {
		return "", "", fmt.Errorf("single: empty keyID")
	}
	data := &NodeKeyData{
		Algorithm:  string(mpc.AlgECDSA),
		KeyID:      keyID,
		NodeID:     nodeID,
		RootPubHex: rootPubHex,
		PrivateKey: priv.D.Text(16),
	}
	if err := store.Save(data); err != nil {
		return "", "", err
	}
	return keyID, rootPubHex, nil
}

func childPrivateKeyECDSA(rootSk *big.Int, rootPubHex, keyID string, accountIndex, change, addrIndex uint32) (*big.Int, error) {
	if rootSk == nil {
		return nil, fmt.Errorf("single: nil root private key")
	}
	root, err := hd.RootPubHexToECDSA(rootPubHex)
	if err != nil {
		return nil, err
	}
	path := hd.PathFromAccountAndAddress(accountIndex, change, addrIndex)
	delta, _, err := hd.DeriveChildPubFromPath(root, hd.ChainCodeFromKeyID(keyID), path)
	if err != nil {
		return nil, err
	}
	n := hd.S256().Params().N
	child := new(big.Int).Add(new(big.Int).Set(rootSk), delta)
	child.Mod(child, n)
	if child.Sign() == 0 {
		return nil, fmt.Errorf("single: invalid child private key")
	}
	return child, nil
}

// SignECDSA 使用调整后的子私钥对 32 字节 tx hash 签名，输出 R||S hex（64 字节）。
func SignECDSA(data *NodeKeyData, accountIndex, change, addrIndex uint32, msgHashHex string) (string, error) {
	if data == nil {
		return "", fmt.Errorf("single: nil key data")
	}
	msgHash, err := hd.MessageHashFromTxHash(msgHashHex)
	if err != nil {
		return "", err
	}
	rootSk, err := parseRootPrivateKey(data)
	if err != nil {
		return "", err
	}
	childSk, err := childPrivateKeyECDSA(rootSk, data.RootPubHex, data.KeyID, accountIndex, change, addrIndex)
	if err != nil {
		return "", err
	}
	x, y := hd.S256().ScalarBaseMult(hd.Pad32(childSk.Bytes()))
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: hd.S256(), X: x, Y: y},
		D:         childSk,
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hd.Pad32(msgHash.Bytes()))
	if err != nil {
		return "", fmt.Errorf("single: ecdsa sign: %w", err)
	}
	sig := append(hd.Pad32(r.Bytes()), hd.Pad32(s.Bytes())...)
	return hex.EncodeToString(sig), nil
}

// KeygenEd25519 生成 Ed25519 根密钥对并落盘（标量与 FROST share 同语义）。
func KeygenEd25519(store *FileKeyStore, nodeID string) (keyID, rootPubHex string, err error) {
	if store == nil {
		return "", "", fmt.Errorf("single: nil keystore")
	}
	curve := edwards.Edwards()
	n := hd.Ed25519Order()
	rootSk, err := rand.Int(rand.Reader, n)
	if err != nil {
		return "", "", fmt.Errorf("single: generate ed25519 scalar: %w", err)
	}
	if rootSk.Sign() == 0 {
		return "", "", fmt.Errorf("single: invalid ed25519 scalar")
	}
	skBytes := edwards.BigIntToEncodedBytesNoReverse(rootSk)
	priv, pubKey, err := edwards.PrivKeyFromScalar(curve, skBytes[:])
	if err != nil {
		return "", "", fmt.Errorf("single: ed25519 pubkey from scalar: %w", err)
	}
	_ = priv
	pubBytes := pubKey.SerializeCompressed()
	rootPubHex = hex.EncodeToString(pubBytes)
	keyID, err = hd.KeyIDFromEd25519PubHex(rootPubHex)
	if err != nil {
		return "", "", err
	}
	data := &NodeKeyData{
		Algorithm:  string(mpc.AlgEd25519),
		KeyID:      keyID,
		NodeID:     nodeID,
		RootPubHex: rootPubHex,
		PrivateKey: rootSk.Text(16),
	}
	if err := store.Save(data); err != nil {
		return "", "", err
	}
	return keyID, rootPubHex, nil
}

func childPrivateKeyEd25519(rootSk *big.Int, rootPubHex, keyID string, accountIndex, change, addrIndex uint32) (*big.Int, error) {
	if rootSk == nil {
		return nil, fmt.Errorf("single: nil root private key")
	}
	path := hd.PathFromAccountAndAddress(accountIndex, change, addrIndex)
	delta, _, err := hd.DeriveEd25519ChildPubFromPath(rootPubHex, hd.ChainCodeFromKeyID(keyID), path)
	if err != nil {
		return nil, err
	}
	n := hd.Ed25519Order()
	child := new(big.Int).Add(new(big.Int).Set(rootSk), delta)
	child.Mod(child, n)
	if child.Sign() == 0 {
		return nil, fmt.Errorf("single: invalid child private key")
	}
	return child, nil
}

// SignEd25519 对消息原始字节签名，输出 64 字节 hex。
func SignEd25519(data *NodeKeyData, accountIndex, change, addrIndex uint32, messageHex string) (string, error) {
	if data == nil {
		return "", fmt.Errorf("single: nil key data")
	}
	msg, err := hex.DecodeString(messageHex)
	if err != nil {
		return "", fmt.Errorf("single: decode message: %w", err)
	}
	rootSk, err := parseRootPrivateKey(data)
	if err != nil {
		return "", err
	}
	childSk, err := childPrivateKeyEd25519(rootSk, data.RootPubHex, data.KeyID, accountIndex, change, addrIndex)
	if err != nil {
		return "", err
	}
	skBytes := edwards.BigIntToEncodedBytesNoReverse(childSk)
	priv, _, err := edwards.PrivKeyFromScalar(edwards.Edwards(), skBytes[:])
	if err != nil {
		return "", fmt.Errorf("single: ed25519 child key: %w", err)
	}
	r, s, err := edwards.Sign(edwards.Edwards(), priv, msg)
	if err != nil {
		return "", fmt.Errorf("single: ed25519 sign: %w", err)
	}
	return hex.EncodeToString(edwards.NewSignature(r, s).Serialize()), nil
}
