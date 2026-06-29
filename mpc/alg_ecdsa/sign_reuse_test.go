package alg_ecdsa

import (
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"context"
	"math/big"
	"testing"
	"time"

	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

func TestSignTwiceSameRefreshDifferentMessages(t *testing.T) {
	shares := map[string]NodeShareData{
		"node1": loadShare(t, "node1"),
		"node2": loadShare(t, "node2"),
	}
	participants := mpc.SortedNodeIDs([]string{"node1", "node2"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	msg1, err := hd.MessageHashFromTxHash("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := hd.MessageHashFromTxHash("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	if err != nil {
		t.Fatal(err)
	}

	refreshOut := make(map[string]*refreshpkg.Result)
	signRound := func(msgHash *big.Int, doRefresh bool) error {
		inboxes := map[string]*Inbox{
			"node1": NewInbox(),
			"node2": NewInbox(),
		}
		errCh := make(chan error, 2)
		for _, selfID := range participants {
			selfID := selfID
			share := shares[selfID]
			go func() {
				send := func(target, wireB64 string) error {
					return inboxes[target].Deliver(selfID, wireB64)
				}
				pm := NewWSPeerManager(selfID, participants, send)
				var r *refreshpkg.Result
				if doRefresh {
					r, err = RunRefresh(ctx, selfID, participants, share.Threshold, &share, pm, inboxes[selfID])
					if err != nil {
						errCh <- err
						return
					}
					refreshOut[selfID] = r
				} else {
					r = refreshOut[selfID]
				}
				_, err := RunSign(ctx, selfID, participants, share.Threshold, &share, r, msgHash, 0, 0, 0, pm, inboxes[selfID])
				errCh <- err
			}()
		}
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				return err
			}
		}
		return nil
	}

	if err := signRound(msg1, true); err != nil {
		t.Fatalf("refresh+sign1: %v", err)
	}
	if err := signRound(msg2, false); err != nil {
		t.Fatalf("sign2 same refresh: %v (alice: %q)", err, mpc.LastAliceProtocolLog())
	}
}
