package alg_single

import (
	"fmt"

	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/types"
)

// RunKeygen 按算法执行单签 Keygen 并落盘。
func RunKeygen(alg mpc.Algorithm, store *FileKeyStore, nodeID string) (keyID, rootPubHex string, err error) {
	switch alg {
	case mpc.AlgECDSA:
		return KeygenECDSA(store, nodeID)
	case mpc.AlgEd25519:
		return KeygenEd25519(store, nodeID)
	default:
		return "", "", fmt.Errorf("single: unsupported algorithm %s", alg)
	}
}

// RunSign 按算法对 SignData 执行单签。
func RunSign(data *NodeKeyData, signData types.SignData) (signatureHex string, err error) {
	if data == nil {
		return "", fmt.Errorf("single: nil key data")
	}
	accountIndex, change, addressIndex, err := signHDIndices(signData)
	if err != nil {
		return "", err
	}
	switch mpc.Algorithm(data.Algorithm) {
	case mpc.AlgECDSA:
		return SignECDSA(data, accountIndex, change, addressIndex, signData.Message)
	case mpc.AlgEd25519:
		return SignEd25519(data, accountIndex, change, addressIndex, signData.Message)
	default:
		return "", fmt.Errorf("single: unsupported algorithm %s", data.Algorithm)
	}
}

func signHDIndices(signData types.SignData) (accountIndex, change, addressIndex uint32, err error) {
	if signData.AccountIndex < 0 || signData.Change < 0 || signData.AddressIndex < 0 {
		return 0, 0, 0, fmt.Errorf("single: negative HD index")
	}
	return uint32(signData.AccountIndex), uint32(signData.Change), uint32(signData.AddressIndex), nil
}
