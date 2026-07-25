package alg_single

import (
	"testing"

	mpcecdsa "github.com/godaddy-x/wallet-mpc-node/mpc/ecdsa"
	mpced25519 "github.com/godaddy-x/wallet-mpc-node/mpc/ed25519"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

func testKeystoreKey(t *testing.T) {
	t.Helper()
	keystore.SetEncryptionKey("test-single-key-passphrase")
	t.Cleanup(func() { keystore.SetEncryptionKey("") })
}

func TestSingleECDSAKeygenSignHD(t *testing.T) {
	testKeystoreKey(t)
	dir := t.TempDir()
	store := NewFileKeyStore(dir)
	keyID, rootPub, err := KeygenECDSA(store, "node0")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(keyID, "node0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLoadedKey(data, keyID, "node0", "ecdsa"); err != nil {
		t.Fatal(err)
	}
	msg := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	sig, err := SignECDSA(data, 0, 0, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := hd.DeriveMPCHDAddress(rootPub, keyID, hd.NewMPCHDPath(0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := mpcecdsa.VerifySignatureHex(addr.AddressPubHex, msg, sig)
	if err != nil || !ok {
		t.Fatalf("verify failed ok=%v err=%v", ok, err)
	}
}

func TestSingleEd25519KeygenSignHD(t *testing.T) {
	testKeystoreKey(t)
	dir := t.TempDir()
	store := NewFileKeyStore(dir)
	keyID, rootPub, err := KeygenEd25519(store, "node0")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(keyID, "node0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLoadedKey(data, keyID, "node0", "ed25519"); err != nil {
		t.Fatal(err)
	}
	msg := "deadbeef"
	sig, err := SignEd25519(data, 0, 0, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := hd.DeriveMPCHDAddressEd25519(rootPub, keyID, hd.NewMPCHDPath(0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := mpced25519.VerifySignatureHex(addr.AddressPubHex, msg, sig)
	if err != nil || !ok {
		t.Fatalf("verify failed ok=%v err=%v", ok, err)
	}
}
