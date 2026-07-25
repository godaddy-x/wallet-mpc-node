package alg_single

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

// ValidateLoadedKey 校验落盘密钥与 Start 请求一致，且私钥可还原 RootPubHex。
func ValidateLoadedKey(data *NodeKeyData, expectKeyID, expectNodeID, expectAlg string) error {
	if data == nil {
		return fmt.Errorf("single: nil key data")
	}
	if strings.TrimSpace(expectKeyID) == "" {
		return fmt.Errorf("single: empty keyID")
	}
	if strings.TrimSpace(data.KeyID) == "" || data.KeyID != expectKeyID {
		return fmt.Errorf("single: keyID mismatch: file=%q expect=%q", data.KeyID, expectKeyID)
	}
	if strings.TrimSpace(data.NodeID) == "" {
		return fmt.Errorf("single: missing nodeID in keystore")
	}
	if data.NodeID != expectNodeID {
		return fmt.Errorf("single: nodeID mismatch: file=%q expect=%q", data.NodeID, expectNodeID)
	}
	alg := strings.TrimSpace(data.Algorithm)
	if alg == "" {
		return fmt.Errorf("single: missing algorithm in keystore")
	}
	if expectAlg = strings.TrimSpace(expectAlg); expectAlg != "" && !strings.EqualFold(alg, expectAlg) {
		return fmt.Errorf("single: algorithm mismatch: file=%q expect=%q", alg, expectAlg)
	}
	if _, err := parseRootPrivateKey(data); err != nil {
		return err
	}
	return nil
}

func parseRootPrivateKey(data *NodeKeyData) (*big.Int, error) {
	if data == nil {
		return nil, fmt.Errorf("single: nil key data")
	}
	rootSk, ok := new(big.Int).SetString(strings.TrimSpace(data.PrivateKey), 16)
	if !ok || rootSk.Sign() <= 0 {
		return nil, fmt.Errorf("single: invalid stored private key")
	}
	var n *big.Int
	switch mpc.Algorithm(data.Algorithm) {
	case mpc.AlgECDSA:
		n = hd.S256().Params().N
	case mpc.AlgEd25519:
		n = hd.Ed25519Order()
	default:
		return nil, fmt.Errorf("single: unsupported algorithm %s", data.Algorithm)
	}
	if rootSk.Cmp(n) >= 0 {
		return nil, fmt.Errorf("single: private key >= curve order")
	}
	if err := assertPrivateKeyMatchesRootPub(data, rootSk); err != nil {
		return nil, err
	}
	return rootSk, nil
}

func assertPrivateKeyMatchesRootPub(data *NodeKeyData, rootSk *big.Int) error {
	want := strings.ToLower(strings.TrimSpace(data.RootPubHex))
	if want == "" {
		return fmt.Errorf("single: missing rootPubHex")
	}
	switch mpc.Algorithm(data.Algorithm) {
	case mpc.AlgECDSA:
		x, y := hd.S256().ScalarBaseMult(hd.Pad32(rootSk.Bytes()))
		got, _ := hd.PubKeyToHex(&ecdsa.PublicKey{Curve: hd.S256(), X: x, Y: y})
		if !strings.EqualFold(strings.TrimSpace(got), want) {
			return fmt.Errorf("single: private key does not match rootPubHex")
		}
		return nil
	case mpc.AlgEd25519:
		skBytes := edwards.BigIntToEncodedBytesNoReverse(rootSk)
		_, pubKey, err := edwards.PrivKeyFromScalar(edwards.Edwards(), skBytes[:])
		if err != nil {
			return fmt.Errorf("single: ed25519 pubkey from scalar: %w", err)
		}
		got := hex.EncodeToString(pubKey.SerializeCompressed())
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("single: private key does not match rootPubHex")
		}
		return nil
	default:
		return fmt.Errorf("single: unsupported algorithm %s", data.Algorithm)
	}
}
