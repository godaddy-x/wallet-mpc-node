package mpc

import "testing"

func TestInferAlgorithmFromPubHexECDSA(t *testing.T) {
	pub := "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A723B04810E53A0806DD6B35"
	got, err := InferAlgorithmFromPubHex(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != AlgECDSA {
		t.Fatalf("got %q, want ecdsa", got)
	}
}

func TestInferAlgorithmFromPubHexEd25519(t *testing.T) {
	pub := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	got, err := InferAlgorithmFromPubHex(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != AlgEd25519 {
		t.Fatalf("got %q, want ed25519", got)
	}
}

func TestAssertPubHexMatchesAlgorithmMismatch(t *testing.T) {
	pub := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	if err := AssertPubHexMatchesAlgorithm(AlgECDSA, pub); err == nil {
		t.Fatal("expected mismatch error")
	}
}
