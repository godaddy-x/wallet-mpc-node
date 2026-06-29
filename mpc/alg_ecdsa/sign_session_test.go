package alg_ecdsa

import (
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"context"
	"testing"
	"time"

	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

func TestSignSessionSubsetTwoOfThree(t *testing.T) {
	ClearSignMaterialPool()
	defer ClearSignMaterialPool()

	shares := map[string]NodeShareData{
		"node1": loadShare(t, "node1"),
		"node2": loadShare(t, "node2"),
	}
	participants := mpc.SortedNodeIDs([]string{"node1", "node2"})
	inboxes := map[string]*Inbox{
		"node1": NewInbox(),
		"node2": NewInbox(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	msgHash, err := hd.MessageHashFromTxHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	if err := warmSignMaterialForTest(t, ctx, participants, shares); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 2)
	sigCh := make(chan string, 2)
	for _, selfID := range participants {
		selfID := selfID
		share := shares[selfID]
		go func() {
			send := func(target, wireB64 string) error {
				return inboxes[target].Deliver(selfID, wireB64)
			}
			pm := NewWSPeerManager(selfID, participants, send)
			out, err := RunSignSession(
				ctx,
				"test-sign-session",
				selfID,
				participants,
				share.Threshold,
				&share,
				msgHash,
				0, 0, 0,
				pm,
				inboxes[selfID],
			)
			if err != nil {
				errCh <- err
				return
			}
			sigCh <- out.SignatureHex
			errCh <- nil
		}()
	}

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		t.Fatalf("sign session failed: %v (alice: %q)", firstErr, mpc.LastAliceProtocolLog())
	}
	sig1 := <-sigCh
	sig2 := <-sigCh
	if sig1 == "" || sig2 == "" {
		t.Fatal("empty signature")
	}
	if sig1 != sig2 {
		t.Fatalf("signature mismatch: %s vs %s", sig1, sig2)
	}
}

func TestComputeSharedSSIDMatchesAcrossNodes(t *testing.T) {
	s1 := loadShare(t, "node1")
	s2 := loadShare(t, "node2")
	ssid1, err := ComputeSharedSSID("task", &s1)
	if err != nil {
		t.Fatal(err)
	}
	ssid2, err := ComputeSharedSSID("task", &s2)
	if err != nil {
		t.Fatal(err)
	}
	if string(ssid1) != string(ssid2) {
		t.Fatal("shared SSID differs between nodes")
	}
}
