package hd

import (
	"testing"
)

const testRootPubHex = "04" +
	"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
	"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

func TestDeriveMPCHDThreeLayers(t *testing.T) {
	wallet, err := DeriveMPCHDWallet(testRootPubHex)
	if err != nil {
		t.Fatal(err)
	}
	if wallet.KeyID == "" || wallet.WalletID == "" {
		t.Fatal("empty wallet ids")
	}
	if WalletIDFromKeyID(wallet.KeyID) != wallet.WalletID {
		t.Fatal("walletID inconsistent")
	}

	acc, err := DeriveMPCHDAccount(testRootPubHex, wallet.KeyID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if acc.HDPath != "m/0/0" {
		t.Fatalf("account path: %s", acc.HDPath)
	}
	if acc.AccountID == "" || acc.AccountPubHex == "" {
		t.Fatal("empty account id/pub")
	}

	addr, err := DeriveMPCHDAddress(testRootPubHex, wallet.KeyID, NewMPCHDPath(0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if addr.HDPath != "m/0/0/0/0" {
		t.Fatalf("address path: %s", addr.HDPath)
	}
	if addr.WalletID != wallet.WalletID {
		t.Fatal("walletID mismatch in address layer")
	}
	if addr.AccountID != acc.AccountID {
		t.Fatal("accountID mismatch in address layer")
	}
	if addr.AddressPubHex == "" {
		t.Fatal("empty address pub")
	}
	if addr.AddressPubHex == acc.AccountPubHex {
		t.Fatal("address pub should differ from account pub at index 0/0/0")
	}
}

func TestParseMPCHDPathRoundTrip(t *testing.T) {
	p, err := ParseMPCHDPath("m/0/1/0/5")
	if err != nil {
		t.Fatal(err)
	}
	if p.AccountIndex != 1 || p.Change != 0 || p.AddressIndex != 5 {
		t.Fatalf("unexpected path: %+v", p)
	}
	if p.FormatAddress() != "m/0/1/0/5" {
		t.Fatalf("format: %s", p.FormatAddress())
	}
}

func TestLegacyWrappersMatchLayers(t *testing.T) {
	wallet, _ := DeriveMPCHDWallet(testRootPubHex)
	accID, accPub, err := DeriveMPCAccountFromRootPubHex(testRootPubHex, wallet.KeyID, 1)
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := DeriveMPCHDAccount(testRootPubHex, wallet.KeyID, 1)
	if accID != acc.AccountID || accPub != acc.AccountPubHex {
		t.Fatal("account wrapper mismatch")
	}
	addrPub, err := DeriveMPCAddressPubFromRootPubHex(testRootPubHex, wallet.KeyID, 1, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := DeriveMPCHDAddress(testRootPubHex, wallet.KeyID, NewMPCHDPath(1, 0, 2))
	if addrPub != addr.AddressPubHex {
		t.Fatal("address wrapper mismatch")
	}
}
