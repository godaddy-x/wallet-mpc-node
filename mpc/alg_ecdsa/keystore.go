package alg_ecdsa

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	dkgpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

// NodeShareData 节点本地持久化的 CGGMP 根份额（DKG + partial pub keys）。
type NodeShareData struct {
	Version         string             `json:"version"`
	KeyID           string             `json:"keyID"`
	NodeID          string             `json:"nodeID"`
	SessionID       string             `json:"sessionId"`
	Share           string             `json:"share"`
	PubX            string             `json:"pubX"`
	PubY            string             `json:"pubY"`
	Rid             string             `json:"rid"`
	Bks             map[string]BkJSON  `json:"bks"`
	PartialPubKeys  map[string]PubJSON `json:"partialPubKeys"`
	AllNodeIDs      []string           `json:"allNodeIDs"`
	Threshold       uint32             `json:"threshold"`
}

// FileKeyStore CGGMP 份额文件存储：BaseDir/{keyID}-{nodeID}.json
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
	return filepath.Join(f.BaseDir, sanitizePathPart(keyID)+"-"+sanitizePathPart(nodeID)+".json")
}

func (f *FileKeyStore) Save(data *NodeShareData) error {
	if data == nil {
		return fmt.Errorf("ecdsa: nil share data")
	}
	data.Version = ProtocolVersion
	path := f.path(data.KeyID, data.NodeID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
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
	return os.WriteFile(path, payload, 0600)
}

func (f *FileKeyStore) Load(keyID, nodeID string) (*NodeShareData, error) {
	raw, err := os.ReadFile(f.path(keyID, nodeID))
	if err != nil {
		return nil, err
	}
	plain, err := keystore.UnwrapCiphertext(raw)
	if err != nil {
		return nil, err
	}
	var data NodeShareData
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// BuildNodeShareData 从 DKG 结果构造可落盘结构。
func BuildNodeShareData(keyID, nodeID, sessionID string, allNodeIDs []string, threshold uint32, result *dkgpkg.Result, partialPubKeys map[string]PubJSON) *NodeShareData {
	return &NodeShareData{
		Version:        ProtocolVersion,
		KeyID:          keyID,
		NodeID:         nodeID,
		SessionID:      sessionID,
		Share:          result.Share.String(),
		PubX:           result.PublicKey.GetX().String(),
		PubY:           result.PublicKey.GetY().String(),
		Rid:            fmt.Sprintf("%x", result.Rid),
		Bks:            bksToJSON(result.Bks),
		PartialPubKeys: partialPubKeys,
		AllNodeIDs:     append([]string(nil), allNodeIDs...),
		Threshold:      threshold,
	}
}
