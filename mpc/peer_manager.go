package mpc

import (
	"fmt"

	"google.golang.org/protobuf/proto"
)

type SendWireFunc func(targetNodeID, wireB64 string) error
type ModuleForProtoFunc func(msg proto.Message) (byte, error)

// WSPeerManager 适配 Alice PeerManager 到 WebSocket 转发。
type WSPeerManager struct {
	label       string
	selfID      string
	peerIDs     []string
	send        SendWireFunc
	moduleFor   ModuleForProtoFunc
}

func NewWSPeerManager(selfID string, allNodeIDs []string, send SendWireFunc, moduleFor ModuleForProtoFunc, label string) *WSPeerManager {
	peers := make([]string, 0, len(allNodeIDs))
	for _, id := range allNodeIDs {
		if id != selfID {
			peers = append(peers, id)
		}
	}
	return &WSPeerManager{label: label, selfID: selfID, peerIDs: peers, send: send, moduleFor: moduleFor}
}

func (p *WSPeerManager) NumPeers() uint32 {
	return uint32(len(p.peerIDs))
}

func (p *WSPeerManager) SelfID() string {
	return p.selfID
}

func (p *WSPeerManager) PeerIDs() []string {
	out := append([]string(nil), p.peerIDs...)
	return out
}

func (p *WSPeerManager) SendWire(targetNodeID, wireB64 string) error {
	if p.send == nil {
		return fmt.Errorf("%s: nil send func", p.label)
	}
	return p.send(targetNodeID, wireB64)
}

func (p *WSPeerManager) MustSend(id string, msg interface{}) {
	pm, ok := msg.(proto.Message)
	if !ok || pm == nil {
		return
	}
	mod, err := p.moduleFor(pm)
	if err != nil {
		return
	}
	bz, err := proto.Marshal(pm)
	if err != nil {
		return
	}
	_ = p.send(id, EncodeWire(mod, bz))
}
