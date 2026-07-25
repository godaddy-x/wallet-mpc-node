package alg_single

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

// NodeKeyData 单签节点本地持久化的完整私钥。
type NodeKeyData struct {
	Type       string `json:"type"`
	Version    string `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"keyID"`
	NodeID     string `json:"nodeID"`
	RootPubHex string `json:"rootPubHex"`
	PrivateKey string `json:"privateKey"` // scalar hex (mod curve order)
}

// FileKeyStore 单签密钥文件：BaseDir/{keyID}-{nodeID}.single.json
type FileKeyStore struct {
	BaseDir string
}

func NewFileKeyStore(baseDir string) *FileKeyStore {
	return &FileKeyStore{BaseDir: baseDir}
}

func sanitizePathPart(s string) string {
	s = strings.ReplaceAll(s, string(filepath.Separator), "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	if s == "" {
		return "_"
	}
	return s
}

func (f *FileKeyStore) path(keyID, nodeID string) string {
	return filepath.Join(f.BaseDir, sanitizePathPart(keyID)+"-"+sanitizePathPart(nodeID)+".single.json")
}

func (f *FileKeyStore) Save(data *NodeKeyData) error {
	if data == nil {
		return fmt.Errorf("single: nil key data")
	}
	data.Type = KeyStoreType
	data.Version = ProtocolVersion
	path := f.path(data.KeyID, data.NodeID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	payload, err := keystore.WrapPlaintext(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func (f *FileKeyStore) Load(keyID, nodeID string) (*NodeKeyData, error) {
	raw, err := os.ReadFile(f.path(keyID, nodeID))
	if err != nil {
		return nil, err
	}
	plain, err := keystore.UnwrapCiphertext(raw)
	if err != nil {
		return nil, err
	}
	var data NodeKeyData
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, err
	}
	if data.Type != "" && data.Type != KeyStoreType {
		return nil, fmt.Errorf("single: unexpected keystore type %q", data.Type)
	}
	return &data, nil
}

func (f *FileKeyStore) Exists(keyID, nodeID string) bool {
	_, err := os.Stat(f.path(keyID, nodeID))
	return err == nil
}

func ParseAlgorithm(s string) (mpc.Algorithm, error) {
	return mpc.ParseAlgorithm(s)
}
