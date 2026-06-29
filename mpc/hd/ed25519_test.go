package hd

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards"
)

func ed25519TestRootPubHex(t *testing.T) (rootHex, keyID string) {
	t.Helper()
	priv, err := edwards.GeneratePrivateKey(edwards.Edwards())
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PubKey().SerializeCompressed()
	rootHex = hex.EncodeToString(pub)
	keyID = KeyIDFromEd25519PubBytes(pub)
	if keyID == "" {
		t.Fatal("empty keyID")
	}
	return rootHex, keyID
}

func TestDeriveMPCHDThreeLayersEd25519(t *testing.T) {
	rootHex, keyID := ed25519TestRootPubHex(t)
	if WalletIDFromKeyID(keyID) == "" {
		t.Fatal("empty walletID")
	}

	acc, err := DeriveMPCHDAccountEd25519(rootHex, keyID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if acc.HDPath != "m/0/0" {
		t.Fatalf("account path: %s", acc.HDPath)
	}
	if acc.AccountID == "" || len(acc.AccountPubHex) != 64 {
		t.Fatalf("unexpected account pub: %s", acc.AccountPubHex)
	}

	addr, err := DeriveMPCHDAddressEd25519(rootHex, keyID, NewMPCHDPath(0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if addr.HDPath != "m/0/0/0/0" {
		t.Fatalf("address path: %s", addr.HDPath)
	}
	if addr.AddressPubHex == acc.AccountPubHex {
		t.Fatal("address pub should differ from account pub at m/0/0/0/0")
	}
}

func TestDeriveMPCHDAccountEd25519Deterministic(t *testing.T) {
	rootHex, keyID := ed25519TestRootPubHex(t)

	a1, err := DeriveMPCHDAccountEd25519(rootHex, keyID, 1)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := DeriveMPCHDAccountEd25519(rootHex, keyID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a1.AccountPubHex != a2.AccountPubHex || a1.AccountID != a2.AccountID {
		t.Fatal("ed25519 account derive not deterministic")
	}
}
