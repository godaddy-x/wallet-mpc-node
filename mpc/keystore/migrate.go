package keystore

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsEncrypted 判断分片文件是否已为 at-rest 加密格式。
func IsEncrypted(raw []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(raw), []byte(encPrefix))
}

// EncryptShardFileInPlace 将单个明文 JSON 分片文件原地加密；已加密则跳过。
func EncryptShardFileInPlace(path string) (encrypted bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if IsEncrypted(raw) {
		return false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false, fmt.Errorf("keystore: %s is not encrypted and not JSON object", path)
	}
	payload, err := WrapPlaintext(trimmed)
	if err != nil {
		return false, err
	}
	tmp := path + ".encrypting"
	if err := os.WriteFile(tmp, payload, 0600); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// MigratePlaintextDir 将目录下所有 *.json 明文分片批量加密；已加密文件计入 skipped。
func MigratePlaintextDir(dir string) (migrated, skipped int, err error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return 0, 0, fmt.Errorf("keystore: keys directory is empty")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return migrated, skipped, readErr
		}
		if IsEncrypted(raw) {
			skipped++
			continue
		}
		if ok, encErr := EncryptShardFileInPlace(path); encErr != nil {
			return migrated, skipped, encErr
		} else if ok {
			migrated++
		}
	}
	return migrated, skipped, nil
}
