package alg_ecdsa

import (
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
)

const testKeyID = "fb8ae991dbf47ac409438a8ab86d6dee4d3ea3f3dffb8992940e771cfd1cb279"

func loadShare(t *testing.T, nodeID string) NodeShareData {
	t.Helper()
	keyDir := filepath.Join("..", "..", "node", "keys")
	raw, err := os.ReadFile(filepath.Join(keyDir, testKeyID+"-"+nodeID+".json"))
	if err != nil {
		t.Skip("share file not present:", err)
	}
	var share NodeShareData
	if err := json.Unmarshal(raw, &share); err != nil {
		t.Fatal(err)
	}
	return share
}

func runRefreshMesh(
	t *testing.T,
	ctx context.Context,
	participants []string,
	shares map[string]NodeShareData,
	sharedSSID bool,
	filterBKs bool,
) error {
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
			dkgRes, err := dkgResultFromPersist(&share)
			if err != nil {
				errCh <- err
				return
			}
			partialPub, err := pubMapFromJSON(share.PartialPubKeys)
			if err != nil {
				errCh <- err
				return
			}
			bks := dkgRes.Bks
			if filterBKs {
				var ferr error
				bks, partialPub, ferr = FilterParticipantMaps(participants, selfID, dkgRes.Bks, partialPub)
				if ferr != nil {
					errCh <- ferr
					return
				}
			}
			var ssid []byte
			if sharedSSID {
				ssid, err = ComputeSharedSSID("test-refresh", &share)
				if err != nil {
					errCh <- err
					return
				}
			} else {
				ssid = cggmp.ComputeSSID(
					[]byte("test-refresh"),
					[]byte(dkgRes.Bks[selfID].String(dkgRes.PublicKey.GetCurve().Params().N)),
					dkgRes.Rid,
				)
			}
			send := func(target, wireB64 string) error {
				_ = inboxes[target].Deliver(selfID, wireB64)
				return nil
			}
			pm := NewWSPeerManager(selfID, participants, send)
			listener := mpc.NewAliceListener("cggmp")
			core, err := refreshpkg.NewRefresh(
				dkgRes.Share,
				dkgRes.PublicKey,
				pm,
				share.Threshold,
				partialPub,
				bks,
				2048,
				ssid,
				listener,
			)
			if err != nil {
				errCh <- err
				return
			}
			errCh <- RunBackend(ctx, core, inboxes[selfID], listener, refreshTimeout)
		}()
	}
	var firstErr error
	for range participants {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func TestRefreshAllThreePartiesSharedSSID(t *testing.T) {
	shares := map[string]NodeShareData{
		"node0": loadShare(t, "node0"),
		"node1": loadShare(t, "node1"),
		"node2": loadShare(t, "node2"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	participants := mpc.SortedNodeIDs([]string{"node0", "node1", "node2"})
	if err := runRefreshMesh(t, ctx, participants, shares, true, false); err != nil {
		t.Fatalf("3-party shared ssid refresh failed: %v (alice: %q)", err, mpc.LastAliceProtocolLog())
	}
}

func TestRefreshSubsetTwoOfThreeFiltered(t *testing.T) {
	shares := map[string]NodeShareData{
		"node1": loadShare(t, "node1"),
		"node2": loadShare(t, "node2"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	participants := mpc.SortedNodeIDs([]string{"node1", "node2"})
	if err := runRefreshMesh(t, ctx, participants, shares, true, true); err != nil {
		t.Fatalf("2-party filtered shared ssid refresh failed: %v (alice: %q)", err, mpc.LastAliceProtocolLog())
	}
}
