package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godaddy-x/freego/utils/crypto"
)

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file %s: %v", path, err)
	}
}

func assertProvisionEncrypted(t *testing.T, result *crypto.Plan2ProvisionResult, wrapKey string) {
	t.Helper()
	if result == nil {
		t.Fatal("result is nil")
	}
	assertFileExists(t, result.PublicPath())
	assertFileExists(t, result.PrivatePath())

	pub, err := crypto.ReadPlan2PublicKey(result.Dir)
	if err != nil {
		t.Fatal("read public:", err)
	}
	priv, err := crypto.ReadPlan2PrivateKey(result.Dir, wrapKey)
	if err != nil {
		t.Fatal("read private:", err)
	}
	if err := crypto.ValidateMLDSA87PublicKeyB64(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.CreateMLDSA87WithBase64(priv, pub); err != nil {
		t.Fatal("load cipher:", err)
	}
}

func assertProvisionMLDSARoundtrip(t *testing.T, result *crypto.Plan2ProvisionResult, wrapKey string) {
	t.Helper()
	if result == nil {
		t.Fatal("result is nil")
	}
	assertFileExists(t, result.PublicPath())
	assertFileExists(t, result.PrivatePath())

	pub, err := crypto.ReadPlan2PublicKey(result.Dir)
	if err != nil {
		t.Fatal("read public.pem:", err)
	}
	priv, err := crypto.ReadPlan2PrivateKey(result.Dir, wrapKey)
	if err != nil {
		t.Fatal("read private.key:", err)
	}
	if err := crypto.ValidateMLDSA87PublicKeyB64(pub); err != nil {
		t.Fatal("validate public:", err)
	}

	cipher, err := crypto.CreateMLDSA87WithBase64(priv, pub)
	if err != nil {
		t.Fatal("load MLDSA:", err)
	}
	msg := []byte("wallet-mpc-node genkey plaintext roundtrip")
	sig, err := cipher.Sign(msg)
	if err != nil {
		t.Fatal("sign:", err)
	}
	if err := cipher.Verify(msg, sig); err != nil {
		t.Fatal("verify:", err)
	}
}

func assertProvisionPlaintext(t *testing.T, result *crypto.Plan2ProvisionResult) {
	t.Helper()
	assertProvisionEncrypted(t, result, "")
}

func TestRunGenKeyEncrypted(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), crypto.Plan2DefaultProvisionDir)
	t.Setenv(crypto.Plan2WrapKeyEnv, "test-wrap-key")

	result, err := runGenKey(false, outDir)
	if err != nil {
		t.Fatal(err)
	}
	assertProvisionEncrypted(t, result, "test-wrap-key")
}

func TestRunGenKeyPlaintext(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), crypto.Plan2DefaultProvisionDir)
	t.Setenv(crypto.Plan2WrapKeyEnv, "")

	result, err := runGenKey(false, outDir)
	if err != nil {
		t.Fatal(err)
	}
	assertProvisionPlaintext(t, result)
	assertProvisionMLDSARoundtrip(t, result, "")
}

func TestRunGenKeyEncRequiresWrapKey(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "no-output")
	t.Setenv(crypto.Plan2WrapKeyEnv, "")

	if _, err := runGenKey(true, outDir); err == nil {
		t.Fatal("expected error when -enc without MPC_PLAN2_WRAP_KEY")
	}
}
