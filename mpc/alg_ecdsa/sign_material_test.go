package alg_ecdsa

import (
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"context"
	"testing"
)

func warmSignMaterialForTest(t *testing.T, ctx context.Context, participants []string, shares map[string]NodeShareData) error {
	t.Helper()
	inboxes := make(map[string]*Inbox, len(participants))
	for _, id := range participants {
		inboxes[id] = NewInbox()
	}
	errCh := make(chan error, len(participants))
	for _, selfID := range participants {
		selfID := selfID
		share := shares[selfID]
		go func() {
			send := func(target, wireB64 string) error {
				return inboxes[target].Deliver(selfID, wireB64)
			}
			pm := NewWSPeerManager(selfID, participants, send)
			errCh <- RunWarmRefresh(ctx, selfID, participants, share.Threshold, &share, pm, inboxes[selfID])
		}()
	}
	for range participants {
		if err := <-errCh; err != nil {
			return err
		}
	}
	return nil
}

func TestSignMaterialPoolAcquire(t *testing.T) {
	ClearSignMaterialPool()
	defer ClearSignMaterialPool()

	shares := map[string]NodeShareData{
		"node1": loadShare(t, "node1"),
		"node2": loadShare(t, "node2"),
	}
	participants := mpc.SortedNodeIDs([]string{"node1", "node2"})
	ctx := context.Background()

	if err := warmSignMaterialForTest(t, ctx, participants, shares); err != nil {
		t.Fatal(err)
	}
	key := MaterialSessionKey(shares["node1"].KeyID, "node1", participants)
	if !DefaultSignMaterialPool.HasReady(key) {
		t.Fatal("expected warm material ready")
	}
	acq, err := DefaultSignMaterialPool.Acquire(key)
	if err != nil {
		t.Fatal(err)
	}
	if acq.NeedWarm {
		t.Fatal("unexpected needWarm on first acquire")
	}
	if acq.UseCount != 1 {
		t.Fatalf("expected useCount=1 got %d", acq.UseCount)
	}
}
