package alg_ed25519

import (
	"context"
	"fmt"
	"time"

	dkgpkg "github.com/getamis/alice/crypto/tss/dkg"
	fdkg "github.com/getamis/alice/crypto/tss/eddsa/frost/dkg"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
)

const keygenTimeout = 11 * time.Minute

func RankForIndex(_ int, _ uint32) uint32 { return 0 }

func RunDKG(
	ctx context.Context,
	selfNodeID string,
	allNodeIDs []string,
	threshold uint32,
	pm *WSPeerManager,
	inbox *Inbox,
) (*dkgpkg.Result, error) {
	myIdx := mpc.IndexOf(allNodeIDs, selfNodeID)
	if myIdx < 0 {
		return nil, fmt.Errorf("frost: self node %s not in participant list", selfNodeID)
	}
	rank := RankForIndex(myIdx, threshold)
	listener := mpc.NewAliceListener("frost")
	core, err := fdkg.NewDKG(pm, threshold, rank, listener)
	if err != nil {
		return nil, err
	}
	if err := RunBackend(ctx, core, inbox, listener, keygenTimeout); err != nil {
		return nil, err
	}
	return core.GetResult()
}
