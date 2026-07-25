package alg_single

import (
	"math/big"
	"testing"

	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

func TestValidateLoadedKeyRejectsMismatch(t *testing.T) {
	testKeystoreKey(t)
	dir := t.TempDir()
	store := NewFileKeyStore(dir)
	keyID, _, err := KeygenECDSA(store, "node0")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(keyID, "node0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLoadedKey(data, "wrong-key-id", "node0", "ecdsa"); err == nil {
		t.Fatal("expected keyID mismatch")
	}
	if err := ValidateLoadedKey(data, keyID, "node1", "ecdsa"); err == nil {
		t.Fatal("expected nodeID mismatch")
	}
	if err := ValidateLoadedKey(data, keyID, "node0", "ed25519"); err == nil {
		t.Fatal("expected algorithm mismatch")
	}
	data.NodeID = ""
	if err := ValidateLoadedKey(data, keyID, "node0", "ecdsa"); err == nil {
		t.Fatal("expected reject empty nodeID in keystore")
	}
}

func TestParseRootPrivateKeyRejectsOutOfRange(t *testing.T) {
	testKeystoreKey(t)
	dir := t.TempDir()
	store := NewFileKeyStore(dir)
	keyID, _, err := KeygenECDSA(store, "node0")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(keyID, "node0")
	if err != nil {
		t.Fatal(err)
	}
	n := new(big.Int).Set(hd.S256().Params().N)
	data.PrivateKey = n.Text(16) // == curve order, invalid
	if _, err := parseRootPrivateKey(data); err == nil {
		t.Fatal("expected reject private key >= curve order")
	}
}

func TestParseRootPrivateKeyRejectsPubMismatch(t *testing.T) {
	testKeystoreKey(t)
	dir := t.TempDir()
	store := NewFileKeyStore(dir)
	keyID, _, err := KeygenECDSA(store, "node0")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(keyID, "node0")
	if err != nil {
		t.Fatal(err)
	}
	// Flip one nibble in rootPubHex while keeping a valid-looking hex length.
	if len(data.RootPubHex) < 4 {
		t.Fatal("unexpected short rootPubHex")
	}
	b := []byte(data.RootPubHex)
	if b[2] == '0' {
		b[2] = '1'
	} else {
		b[2] = '0'
	}
	data.RootPubHex = string(b)
	if _, err := parseRootPrivateKey(data); err == nil {
		t.Fatal("expected reject private key / rootPubHex mismatch")
	}
}
