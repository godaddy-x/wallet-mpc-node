package alg_ecdsa

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
)

const refreshTimeout = 6 * time.Minute

// RefreshSessionKey 稳定会话键：同一 wallet key + 参与节点子集使用相同 SSID。
func RefreshSessionKey(keyID string, participants []string) string {
	return keyID + "|" + strings.Join(mpc.SortedNodeIDs(participants), ",")
}

// ComputeSharedSSID 生成同一签名任务内 refresh/sign 全体参与方共用的 SSID。
// Alice ZK 证明绑定 ssidInfo；若各节点用自身 bk 派生 per-party SSID，
// refresh Round2 与 sign Round1 会报 "the verification is failure"。
func ComputeSharedSSID(sessionID string, dkgData *NodeShareData) ([]byte, error) {
	dkgResult, err := dkgResultFromPersist(dkgData)
	if err != nil {
		return nil, err
	}
	return cggmp.ComputeSSID([]byte(sessionID), []byte{}, dkgResult.Rid), nil
}

// ComputeRefreshSSID 见 ComputeSharedSSID。
func ComputeRefreshSSID(sessionID string, dkgData *NodeShareData) ([]byte, error) {
	return ComputeSharedSSID(sessionID, dkgData)
}

// RunRefresh 签名前 refresh（reshare）以生成 Paillier / Pedersen 等中间态。
func RunRefresh(
	ctx context.Context,
	selfNodeID string,
	participants []string,
	threshold uint32,
	dkgData *NodeShareData,
	pm *WSPeerManager,
	inbox *Inbox,
) (*refreshpkg.Result, error) {
	dkgResult, err := dkgResultFromPersist(dkgData)
	if err != nil {
		return nil, err
	}
	partialPub, err := pubMapFromJSON(dkgData.PartialPubKeys)
	if err != nil {
		return nil, err
	}
	bks, partialPub, err := FilterParticipantMaps(participants, selfNodeID, dkgResult.Bks, partialPub)
	if err != nil {
		return nil, err
	}
	sessionKey := RefreshSessionKey(dkgData.KeyID, participants)
	ssid, err := ComputeSharedSSID(sessionKey, dkgData)
	if err != nil {
		return nil, err
	}
	listener := mpc.NewAliceListener("cggmp")
	inbox.SetExpectedModule(WireModuleRefresh)
	core, err := refreshpkg.NewRefresh(
		dkgResult.Share,
		dkgResult.PublicKey,
		pm,
		threshold,
		partialPub,
		bks,
		2048,
		ssid,
		listener,
	)
	if err != nil {
		return nil, err
	}
	if err := RunBackend(ctx, core, inbox, listener, refreshTimeout); err != nil {
		return nil, fmt.Errorf("cggmp refresh: %w", err)
	}
	return core.GetResult()
}

