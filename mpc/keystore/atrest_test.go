package keystore

import (
	"testing"
)

func TestKeystoreAtRestRoundTrip(t *testing.T) {
	SetEncryptionKey("test-passphrase-k3")
	t.Cleanup(func() { SetEncryptionKey("") })

	plain := []byte(`{"keyID":"k1","share":"secret"}`)
	wrapped, err := WrapPlaintext(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrapped) == string(plain) {
		t.Fatal("expected ciphertext wrapper")
	}
	got, err := UnwrapCiphertext(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestKeystoreAtRestRejectsPlaintext(t *testing.T) {
	SetEncryptionKey("test-passphrase-k3")
	t.Cleanup(func() { SetEncryptionKey("") })

	plain := []byte(`{"version":"1"}`)
	if _, err := UnwrapCiphertext(plain); err != ErrPlaintextShardRejected {
		t.Fatalf("expected ErrPlaintextShardRejected, got %v", err)
	}
}

func TestKeystoreAtRestRequiresKeyToSave(t *testing.T) {
	SetEncryptionKey("")
	if _, err := WrapPlaintext([]byte(`{"x":1}`)); err != ErrEncryptionKeyRequired {
		t.Fatalf("expected ErrEncryptionKeyRequired, got %v", err)
	}
}

func TestKeystoreAtRestRequiresKeyForEncryptedFile(t *testing.T) {
	SetEncryptionKey("key-a")
	wrapped, err := WrapPlaintext([]byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	SetEncryptionKey("")
	if _, err := UnwrapCiphertext(wrapped); err != ErrEncryptionKeyRequired {
		t.Fatalf("expected ErrEncryptionKeyRequired, got %v", err)
	}
}
