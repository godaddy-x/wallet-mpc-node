package alg_ecdsa

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

func TestFileKeyStoreAtRestEncryption(t *testing.T) {
	dir := t.TempDir()
	keystore.SetEncryptionKey("file-keystore-test-key")
	t.Cleanup(func() { keystore.SetEncryptionKey("") })

	store := NewFileKeyStore(dir)
	data := &NodeShareData{
		KeyID:  "kid1",
		NodeID: "node0",
		Share:  "secret-share",
	}
	if err := store.Save(data); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "kid1-node0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 0 && raw[0] == '{' {
		t.Fatal("expected encrypted payload, got plaintext json")
	}
	loaded, err := store.Load("kid1", "node0")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Share != data.Share {
		t.Fatalf("share mismatch: %q", loaded.Share)
	}
}
