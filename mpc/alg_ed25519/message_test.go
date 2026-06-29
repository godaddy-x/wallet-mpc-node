package alg_ed25519

import (
	"encoding/hex"
	"testing"
)

func TestMessageBytesFromHex(t *testing.T) {
	raw := []byte{0x01, 0x02, 0xab}
	got, err := MessageBytesFromHex(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("unexpected bytes: %x", got)
	}
}

func TestMessageBytesFromHexRejectsEmpty(t *testing.T) {
	if _, err := MessageBytesFromHex(""); err == nil {
		t.Fatal("expected error for empty message")
	}
}
