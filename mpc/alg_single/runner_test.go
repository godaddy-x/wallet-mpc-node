package alg_single

import (
	"testing"

	"github.com/godaddy-x/wallet-mpc-node/types"
)

func TestRunSignRejectsNegativeHDIndex(t *testing.T) {
	testKeystoreKey(t)
	dir := t.TempDir()
	store := NewFileKeyStore(dir)
	keyID, _, err := KeygenECDSA(store, "node0", "test-session")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(keyID, "node0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = RunSign(data, types.SignData{AccountIndex: -1})
	if err == nil {
		t.Fatal("expected reject negative account index")
	}
}
