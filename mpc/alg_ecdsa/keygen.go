package alg_ecdsa

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"google.golang.org/protobuf/proto"
)

const keygenTimeout = 11 * time.Minute

// RankForIndex 2-of-n 场景下所有节点 rank=0。
func RankForIndex(_ int, _ uint32) uint32 {
	return 0
}

// RunDKG 执行 CGGMP DKG。
func RunDKG(
	ctx context.Context,
	taskID string,
	selfNodeID string,
	allNodeIDs []string,
	threshold uint32,
	pm *WSPeerManager,
	inbox *Inbox,
) (*dkg.Result, error) {
	myIdx := mpc.IndexOf(allNodeIDs, selfNodeID)
	if myIdx < 0 {
		return nil, fmt.Errorf("ecdsa: self node %s not in participant list", selfNodeID)
	}
	rank := RankForIndex(myIdx, threshold)
	listener := mpc.NewAliceListener("cggmp")
	core, err := dkg.NewDKG(curve(), pm, []byte(taskID), threshold, rank, listener)
	if err != nil {
		return nil, err
	}
	if err := RunBackend(ctx, core, inbox, listener, keygenTimeout); err != nil {
		return nil, err
	}
	return core.GetResult()
}

// PartialPubCollector 收集 partial pub key wire 消息。
type PartialPubCollector struct {
	mu      sync.Mutex
	selfID  string
	want    map[string]struct{}
	partial map[string]PubJSON
}

func NewPartialPubCollector(selfID string, allNodeIDs []string) *PartialPubCollector {
	want := make(map[string]struct{}, len(allNodeIDs))
	for _, id := range allNodeIDs {
		want[id] = struct{}{}
	}
	return &PartialPubCollector{
		selfID:  selfID,
		want:    want,
		partial: make(map[string]PubJSON, len(allNodeIDs)),
	}
}

func (c *PartialPubCollector) AddSelf(share *big.Int) {
	myPartial := ecpointgrouplaw.ScalarBaseMult(curve(), share)
	c.mu.Lock()
	c.partial[c.selfID] = pubToJSON(myPartial)
	c.mu.Unlock()
}

func (c *PartialPubCollector) Deliver(fromNodeID, wireB64 string) error {
	mod, raw, err := mpc.DecodeWire(wireB64)
	if err != nil {
		return err
	}
	if mod != WireModulePartPub {
		return nil
	}
	m := &ecpointgrouplaw.EcPointMessage{}
	if err := proto.Unmarshal(raw, m); err != nil {
		return err
	}
	pt, err := m.ToPoint()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.want[fromNodeID]; !ok {
		return nil
	}
	c.partial[fromNodeID] = pubToJSON(pt)
	return nil
}

func (c *PartialPubCollector) Done() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.partial) >= len(c.want)
}

func (c *PartialPubCollector) Snapshot() map[string]PubJSON {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]PubJSON, len(c.partial))
	for k, v := range c.partial {
		out[k] = v
	}
	return out
}

// RunPartialPubExchange 广播并等待收齐 partial pub keys。
func RunPartialPubExchange(
	ctx context.Context,
	selfNodeID string,
	allNodeIDs []string,
	share *big.Int,
	pm *WSPeerManager,
	collector *PartialPubCollector,
) (map[string]PubJSON, error) {
	collector.AddSelf(share)
	myPartial := ecpointgrouplaw.ScalarBaseMult(curve(), share)
	msg, err := myPartial.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	bz, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	wire := mpc.EncodeWire(WireModulePartPub, bz)
	for _, id := range allNodeIDs {
		if id == selfNodeID {
			continue
		}
		if err := pm.SendWire(id, wire); err != nil {
			return nil, err
		}
	}
	// 与 DKG 共用 ctx（约 11min）。勿单独设短超时：快节点 DKG 先 Done 后，
	// 慢节点（尤其首次冷启动）可能仍在 DKG，过早超时会导致 keygen 假死。
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !collector.Done() {
		select {
		case <-ctx.Done():
			got := len(collector.Snapshot())
			return nil, fmt.Errorf("ecdsa: partial pub exchange timeout (%d/%d): %w", got, len(allNodeIDs), ctx.Err())
		case <-ticker.C:
		}
	}
	return collector.Snapshot(), nil
}
