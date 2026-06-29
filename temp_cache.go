// 节点侧 ML-KEM-1024 临时封装公钥 cache：单 key 存 []byte。
package main

import (
	"errors"
	"fmt"
	"strings"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/utils"
)

const mlkem1024EncapsulationKeyBytes = 1568

func tempPublicKeyCacheKey(mod, subject, taskID string) string {
	return utils.FNV1a64(utils.AddStr(subject, ":", taskID, ":", mod, ":tempPublicKey"))
}

func getTempPublicKey(mod, subject, taskID string) ([]byte, error) {
	value, ok, err := keyCache.Get(tempPublicKeyCacheKey(mod, subject, taskID), nil)
	if err != nil || !ok || value == nil {
		return nil, err
	}
	switch v := value.(type) {
	case []byte:
		if len(v) == 0 {
			return nil, nil
		}
		return append([]byte(nil), v...), nil
	case string:
		b := utils.Base64Decode(strings.TrimSpace(v))
		if len(b) == 0 {
			return nil, nil
		}
		return append([]byte(nil), b...), nil
	default:
		return nil, nil
	}
}

func putTempPublicKeyFromB64(mod, subject, taskID, pubKeyB64 string, ttl int) error {
	if strings.TrimSpace(pubKeyB64) == "" {
		return errors.New("empty ML-KEM encapsulation key")
	}
	ek, err := ecc.LoadMLKEM1024EncapsulationKeyFromBase64(pubKeyB64)
	if err != nil {
		return fmt.Errorf("invalid ML-KEM-1024 encapsulation key: %w", err)
	}
	pubBytes := ecc.GetMLKEM1024EncapsulationKeyBytes(ek)
	if len(pubBytes) != mlkem1024EncapsulationKeyBytes {
		return fmt.Errorf("invalid ML-KEM-1024 key length: got %d want %d", len(pubBytes), mlkem1024EncapsulationKeyBytes)
	}
	return keyCache.Put(tempPublicKeyCacheKey(mod, subject, taskID), append([]byte(nil), pubBytes...), ttl)
}

func clearSignTempKeys(myNodeID, taskID string, allNodeIDs []string) {
	_ = keyCache.Del(utils.FNV1a64(utils.AddStr(myNodeID, ":", taskID, ":sign:tempPrivateKey")))
	for _, id := range allNodeIDs {
		_ = keyCache.Del(tempPublicKeyCacheKey("sign", id, taskID))
	}
}
