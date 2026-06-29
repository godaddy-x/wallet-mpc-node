package alg_ecdsa

import "testing"

func TestMaterialSessionKeyParticipantOrderInvariant(t *testing.T) {
	keyID := "abc123"
	self := "node1"
	a := MaterialSessionKey(keyID, self, []string{"node2", "node1"})
	b := MaterialSessionKey(keyID, self, []string{"node1", "node2"})
	if a != b {
		t.Fatalf("order should not matter: %q vs %q", a, b)
	}
	want := RefreshSessionKey(keyID, []string{"node1", "node2"}) + "|" + self
	if a != want {
		t.Fatalf("got %q want %q", a, want)
	}
}
