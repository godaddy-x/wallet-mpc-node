// Package keystore 提供 MPC 分片文件 at-rest 加密封装（K3）。
package keystore

import (
	"bytes"
	"errors"
	"strings"
	"sync"

	"github.com/godaddy-x/freego/utils"
)

const encPrefix = "mpc-keystore-v1:"

var (
	ErrEncryptionKeyRequired = errors.New("keystore: MPC_KEYSTORE_KEY or keystoreKey required for at-rest encryption")
	ErrPlaintextShardRejected = errors.New("keystore: plaintext shard rejected; file must use mpc-keystore-v1: encryption")
)

var (
	encKeyMu sync.RWMutex
	encKey   []byte
)

// SetEncryptionKey 设置分片落盘 AES-GCM 密钥（由 passphrase SHA256 派生 32 字节）。
// passphrase 为空则清除密钥（仅测试 teardown）。
func SetEncryptionKey(passphrase string) {
	encKeyMu.Lock()
	defer encKeyMu.Unlock()
	passphrase = strings.TrimSpace(passphrase)
	if passphrase == "" {
		encKey = nil
		return
	}
	encKey = utils.SHA256_BASE(utils.Str2Bytes(passphrase))
}

// EncryptionEnabled 是否已配置 at-rest 加密密钥。
func EncryptionEnabled() bool {
	encKeyMu.RLock()
	defer encKeyMu.RUnlock()
	return len(encKey) == 32
}

func keystoreAAD() []byte {
	return utils.Str2Bytes("mpc-keystore-v1")
}

// WrapPlaintext 加密 JSON 明文落盘；未配置密钥则拒绝写入。
func WrapPlaintext(plain []byte) ([]byte, error) {
	encKeyMu.RLock()
	key := append([]byte(nil), encKey...)
	encKeyMu.RUnlock()
	if len(key) == 0 {
		return nil, ErrEncryptionKeyRequired
	}
	b64, err := utils.AesGCMEncryptBase(plain, key, keystoreAAD())
	if err != nil {
		return nil, err
	}
	return append([]byte(encPrefix), utils.Str2Bytes(b64)...), nil
}

// UnwrapCiphertext 解密分片文件；拒绝未加密的历史明文 JSON。
func UnwrapCiphertext(raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, []byte(encPrefix)) {
		return nil, ErrPlaintextShardRejected
	}
	encKeyMu.RLock()
	key := append([]byte(nil), encKey...)
	encKeyMu.RUnlock()
	if len(key) == 0 {
		return nil, ErrEncryptionKeyRequired
	}
	b64 := string(bytes.TrimPrefix(raw, []byte(encPrefix)))
	return utils.AesGCMDecryptBase(b64, key, keystoreAAD())
}
