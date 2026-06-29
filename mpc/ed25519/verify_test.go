package ed25519

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
)

func TestVerifySignatureHexWithDecredSign(t *testing.T) {
	curve := edwards.Edwards()
	priv, err := edwards.GeneratePrivateKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	msg := []byte("mpc ed25519 verify roundtrip")

	r, s, err := edwards.Sign(curve, priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig := edwards.NewSignature(r, s).Serialize()

	ok, err := VerifySignatureHex(pubHex, hex.EncodeToString(msg), hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected valid signature")
	}
}

func TestEncodeSignatureMatchesDecred(t *testing.T) {
	curve := edwards.Edwards()
	priv, err := edwards.GeneratePrivateKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("encode signature parity")

	r, s, err := edwards.Sign(curve, priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	want := edwards.NewSignature(r, s).Serialize()

	rEnc := edwards.BigIntToEncodedBytes(r)
	x, y, err := curve.EncodedBytesToBigIntPoint(rEnc)
	if err != nil {
		t.Fatal(err)
	}
	rPt, err := ecpointgrouplaw.NewECPoint(elliptic.Ed25519(), x, y)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeSignature(rPt, s)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("signature encoding mismatch:\nwant %x\ngot  %x", want, got)
	}
}

func TestVerifySignatureHexRejectsTamperedMessage(t *testing.T) {
	curve := edwards.Edwards()
	priv, err := edwards.GeneratePrivateKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	msg := []byte("original message")
	r, s, err := edwards.Sign(curve, priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig := edwards.NewSignature(r, s).Serialize()

	ok, err := VerifySignatureHex(pubHex, hex.EncodeToString([]byte("tampered")), hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected invalid signature for tampered message")
	}
}

func TestEncodeEd25519PubKeyRoundTrip(t *testing.T) {
	curve := edwards.Edwards()
	priv, err := edwards.GeneratePrivateKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	x, y := priv.Public()
	pt, err := ecpointgrouplaw.NewECPoint(elliptic.Ed25519(), x, y)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncodeEd25519PubKey(pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 32 {
		t.Fatalf("unexpected pubkey length: %d", len(enc))
	}
	gotX, gotY, err := XYFromPubKeyBytes(enc)
	if err != nil {
		t.Fatal(err)
	}
	if gotX.Cmp(x) != 0 || gotY.Cmp(y) != 0 {
		t.Fatalf("pubkey roundtrip mismatch: got (%s,%s) want (%s,%s)", gotX, gotY, x, y)
	}
}
