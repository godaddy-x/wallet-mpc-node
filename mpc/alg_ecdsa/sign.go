package alg_ecdsa

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	signpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/sign"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

const signTimeout = 6 * time.Minute

// SignOutput ECDSA 签名 R||S hex。
type SignOutput struct {
	R               *big.Int
	S               *big.Int
	SignatureHex    string
	NeedRefreshWarm bool
	MaterialUseCount int
	MaterialTier     MaterialUseTier
}

// RunSign 在 refresh 结果上执行 CGGMP 签名。
func RunSign(
	ctx context.Context,
	selfNodeID string,
	participants []string,
	threshold uint32,
	dkgData *NodeShareData,
	refreshResult *refreshpkg.Result,
	msgHash *big.Int,
	accountIndex, change, addrIndex uint32,
	pm *WSPeerManager,
	inbox *Inbox,
) (*SignOutput, error) {
	dkgRes, err := dkgResultFromPersist(dkgData)
	if err != nil {
		return nil, err
	}
	bks, partialPub, err := FilterParticipantMaps(participants, selfNodeID, dkgRes.Bks, refreshResult.PartialPubKey)
	if err != nil {
		return nil, err
	}
	adjShare, childPub, delta, err := AdjustShareAndPubKeyForPath(
		refreshResult.Share,
		dkgRes.PublicKey,
		dkgData.KeyID,
		accountIndex,
		change,
		addrIndex,
	)
	if err != nil {
		return nil, err
	}
	partialPub, err = AdjustPartialPubsForDelta(partialPub, delta)
	if err != nil {
		return nil, err
	}
	sessionKey := RefreshSessionKey(dkgData.KeyID, participants)
	ssid, err := ComputeSharedSSID(sessionKey, dkgData)
	if err != nil {
		return nil, err
	}
	msgBytes := padMsg32(msgHash.Bytes())
	listener := mpc.NewAliceListener("cggmp")
	inbox.SetExpectedModule(WireModuleSign)
	core, err := signpkg.NewSign(
		threshold,
		ssid,
		adjShare,
		childPub,
		partialPub,
		refreshResult.PaillierKey,
		refreshResult.PedParameter,
		bks,
		msgBytes,
		pm,
		listener,
	)
	if err != nil {
		return nil, err
	}
	if err := RunBackend(ctx, core, inbox, listener, signTimeout); err != nil {
		return nil, fmt.Errorf("cggmp sign: %w", err)
	}
	result, err := core.GetResult()
	if err != nil {
		return nil, err
	}
	sig := append(hd.Pad32(result.R.Bytes()), hd.Pad32(result.S.Bytes())...)
	return &SignOutput{
		R:            result.R,
		S:            result.S,
		SignatureHex: hex.EncodeToString(sig),
	}, nil
}

// RunWarmRefresh 仅执行 refresh，结果写入 SignMaterialPool（后台 warm 路径）。
func RunWarmRefresh(
	ctx context.Context,
	selfNodeID string,
	participants []string,
	threshold uint32,
	dkgData *NodeShareData,
	pm *WSPeerManager,
	inbox *Inbox,
) error {
	result, err := RunRefresh(ctx, selfNodeID, participants, threshold, dkgData, pm, inbox)
	if err != nil {
		return err
	}
	sessionKey := MaterialSessionKey(dkgData.KeyID, selfNodeID, participants)
	return DefaultSignMaterialPool.CommitWarm(sessionKey, result)
}

// RunSignSession 在线签名：只消耗 SignMaterialPool 中的 refresh 材料，不跑同步 refresh。
func RunSignSession(
	ctx context.Context,
	taskID string,
	selfNodeID string,
	participants []string,
	threshold uint32,
	dkgData *NodeShareData,
	msgHash *big.Int,
	accountIndex, change, addrIndex uint32,
	pm *WSPeerManager,
	inbox *Inbox,
) (*SignOutput, error) {
	_ = taskID
	materialKey := MaterialSessionKey(dkgData.KeyID, selfNodeID, participants)
	acq, err := DefaultSignMaterialPool.Acquire(materialKey)
	if err != nil {
		return nil, err
	}
	out, err := RunSign(
		ctx,
		selfNodeID,
		participants,
		threshold,
		dkgData,
		acq.Result,
		msgHash,
		accountIndex,
		change,
		addrIndex,
		pm,
		inbox,
	)
	if err != nil {
		return nil, err
	}
	out.NeedRefreshWarm = acq.NeedWarm
	out.MaterialUseCount = acq.UseCount
	out.MaterialTier = acq.Tier
	return out, nil
}

func padMsg32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
