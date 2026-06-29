package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigratePlaintextDir(t *testing.T) {
	SetEncryptionKey("migrate-test-key")
	t.Cleanup(func() { SetEncryptionKey("") })

	dir := t.TempDir()
	path := filepath.Join(dir, "wallet-node0.json")
	plain := []byte(`{"keyID":"k1","nodeID":"node0","share":"secret"}`)
	if err := os.WriteFile(path, plain, 0600); err != nil {
		t.Fatal(err)
	}

	migrated, skipped, err := MigratePlaintextDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 1 || skipped != 0 {
		t.Fatalf("first pass: migrated=%d skipped=%d", migrated, skipped)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(raw) {
		t.Fatal("expected encrypted payload after migration")
	}
	got, err := UnwrapCiphertext(raw)
	if err != nil || string(got) != string(plain) {
		t.Fatalf("round-trip: got=%q err=%v", got, err)
	}

	migrated, skipped, err = MigratePlaintextDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 0 || skipped != 1 {
		t.Fatalf("second pass: migrated=%d skipped=%d", migrated, skipped)
	}
}

func TestMigratePlaintextDirRejectsNonJSON(t *testing.T) {
	SetEncryptionKey("migrate-test-key")
	t.Cleanup(func() { SetEncryptionKey("") })

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt.json")
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MigratePlaintextDir(dir); err == nil {
		t.Fatal("expected error for non-JSON plaintext shard")
	}
}
