package alg_ed25519

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	dkgpkg "github.com/getamis/alice/crypto/tss/dkg"
	fsigner "github.com/getamis/alice/crypto/tss/eddsa/frost/signer"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	mpced25519 "github.com/godaddy-x/wallet-mpc-node/mpc/ed25519"
)

const signTimeout = 6 * time.Minute

type SignOutput struct {
	SignatureHex string
}

func RunSign(
	ctx context.Context,
	selfNodeID string,
	participants []string,
	threshold uint32,
	dkgData *NodeShareData,
	msg []byte,
	accountIndex, change, addrIndex uint32,
	pm *WSPeerManager,
	inbox *Inbox,
) (*SignOutput, error) {
	dkgRes, err := dkgResultFromPersist(dkgData)
	if err != nil {
		return nil, err
	}
	bks, ys, err := FilterParticipantMaps(participants, selfNodeID, dkgRes.Bks, dkgRes.Ys)
	if err != nil {
		return nil, err
	}
	adjShare, childPub, delta, err := AdjustShareAndPubKeyForPath(
		dkgRes.Share,
		dkgRes.PublicKey,
		dkgData.KeyID,
		accountIndex,
		change,
		addrIndex,
	)
	if err != nil {
		return nil, err
	}
	ys, err = AdjustYsForDelta(ys, delta)
	if err != nil {
		return nil, err
	}
	subResult := &dkgpkg.Result{
		PublicKey: childPub,
		Share:     adjShare,
		Bks:       bks,
		Ys:        ys,
	}
	listener := mpc.NewAliceListener("frost")
	inbox.SetExpectedModule(WireModuleSign)
	core, err := fsigner.NewSigner(childPub, pm, threshold, adjShare, subResult, msg, listener)
	if err != nil {
		return nil, err
	}
	if err := RunBackend(ctx, core, inbox, listener, signTimeout); err != nil {
		return nil, fmt.Errorf("frost sign: %w", err)
	}
	result, err := core.GetResult()
	if err != nil {
		return nil, err
	}
	sig, err := mpced25519.EncodeSignature(result.R, result.S)
	if err != nil {
		return nil, err
	}
	return &SignOutput{SignatureHex: hex.EncodeToString(sig)}, nil
}

func MessageBytesFromHex(msgHex string) ([]byte, error) {
	b, err := hex.DecodeString(msgHex)
	if err != nil {
		return nil, fmt.Errorf("frost: invalid message hex: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("frost: empty message")
	}
	return b, nil
}
