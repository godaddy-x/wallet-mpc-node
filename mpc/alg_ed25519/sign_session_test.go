package alg_ed25519

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/godaddy-x/wallet-mpc-node/mpc"
	mpced25519 "github.com/godaddy-x/wallet-mpc-node/mpc/ed25519"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

func TestFROSTKeygenAndSignTwoOfTwo(t *testing.T) {
	participants := mpc.SortedNodeIDs([]string{"node1", "node2"})
	threshold := uint32(2)
	inboxes := map[string]*Inbox{
		"node1": NewInbox(),
		"node2": NewInbox(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	shares := make(map[string]*NodeShareData, len(participants))
	errCh := make(chan error, len(participants))
	for _, selfID := range participants {
		selfID := selfID
		go func() {
			send := func(target, wireB64 string) error {
				return inboxes[target].Deliver(selfID, wireB64)
			}
			pm := NewWSPeerManager(selfID, participants, send)
			result, err := RunDKG(ctx, selfID, participants, threshold, pm, inboxes[selfID])
			if err != nil {
				errCh <- err
				return
			}
			pubHex, err := PubHexFromPoint(result.PublicKey)
			if err != nil {
				errCh <- err
				return
			}
			keyID := KeyIDFromPubHex(pubHex)
			share, err := BuildNodeShareData(keyID, selfID, "frost-test", participants, threshold, result)
			if err != nil {
				errCh <- err
				return
			}
			shares[selfID] = share
			errCh <- nil
		}()
	}
	for range participants {
		if err := <-errCh; err != nil {
			t.Fatalf("dkg: %v (alice: %q)", err, mpc.LastAliceProtocolLog())
		}
	}
	if shares["node1"].KeyID != shares["node2"].KeyID {
		t.Fatalf("keyID mismatch: %s vs %s", shares["node1"].KeyID, shares["node2"].KeyID)
	}

	msg := []byte("mpc frost integration test message")
	msgHex := hex.EncodeToString(msg)
	signErrCh := make(chan error, len(participants))
	sigCh := make(chan string, len(participants))
	for _, selfID := range participants {
		selfID := selfID
		share := shares[selfID]
		go func() {
			send := func(target, wireB64 string) error {
				return inboxes[target].Deliver(selfID, wireB64)
			}
			pm := NewWSPeerManager(selfID, participants, send)
			out, err := RunSign(ctx, selfID, participants, threshold, share, msg, 0, 0, 0, pm, inboxes[selfID])
			if err != nil {
				signErrCh <- err
				return
			}
			sigCh <- out.SignatureHex
			signErrCh <- nil
		}()
	}
	var firstSignErr error
	for range participants {
		if err := <-signErrCh; err != nil && firstSignErr == nil {
			firstSignErr = err
		}
	}
	if firstSignErr != nil {
		t.Fatalf("sign: %v (alice: %q)", firstSignErr, mpc.LastAliceProtocolLog())
	}
	sig1 := <-sigCh
	sig2 := <-sigCh
	if sig1 == "" || sig2 == "" {
		t.Fatal("empty signature")
	}
	if sig1 != sig2 {
		t.Fatalf("signature mismatch: %s vs %s", sig1, sig2)
	}

	pubHex := shares["node1"].PubHex
	addr, err := hd.DeriveMPCHDAddressEd25519(pubHex, shares["node1"].KeyID, hd.NewMPCHDPath(0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := mpced25519.VerifySignatureHex(addr.AddressPubHex, msgHex, sig1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature verify failed")
	}
}
