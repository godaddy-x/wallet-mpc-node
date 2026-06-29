package mpc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/getamis/alice/types"
)

const InboxPendingCap = 256

type UnmarshalWireFunc func(module byte, raw []byte) (types.Message, error)

type inboxPending struct {
	senderNodeID string
	wireKey      string
	module       byte
	msg          types.Message
}

func inboxWireKey(senderNodeID, wireB64 string) string {
	sum := sha256.Sum256([]byte(senderNodeID + "|" + wireB64))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// Inbox 将收到的 wire 消息投递到 Alice MessageMain。
// handler 未就绪时暂存消息，SetHandler 后按序回放。
type Inbox struct {
	label          string
	unmarshal      UnmarshalWireFunc
	mu             sync.Mutex
	handler        func(senderID string, msg types.Message) error
	expectedModule byte
	pending        []inboxPending
}

func NewInbox(label string, unmarshal UnmarshalWireFunc) *Inbox {
	return &Inbox{label: label, unmarshal: unmarshal}
}

func (b *Inbox) SetExpectedModule(module byte) {
	b.mu.Lock()
	b.expectedModule = module
	b.mu.Unlock()
}

func (b *Inbox) SetHandler(h func(senderID string, msg types.Message) error) error {
	b.mu.Lock()
	b.handler = h
	expected := b.expectedModule
	pending := append([]inboxPending(nil), b.pending...)
	b.pending = nil
	b.mu.Unlock()

	var firstErr error
	for _, p := range pending {
		if h == nil {
			continue
		}
		if expected != 0 && p.module != expected {
			continue
		}
		if err := h(p.senderNodeID, p.msg); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("replay from %s: %w", p.msg.GetId(), err)
		}
	}
	return firstErr
}

func (b *Inbox) ClearHandler() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handler = nil
	b.expectedModule = 0
	b.pending = nil
}

func (b *Inbox) PendingLen() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

func (b *Inbox) Deliver(senderNodeID, wireB64 string) error {
	mod, raw, err := DecodeWire(wireB64)
	if err != nil {
		return err
	}
	msg, err := b.unmarshal(mod, raw)
	if err != nil {
		return err
	}
	b.mu.Lock()
	expected := b.expectedModule
	h := b.handler
	if expected != 0 && mod != expected {
		b.mu.Unlock()
		return nil
	}
	if h != nil {
		b.mu.Unlock()
		return h(senderNodeID, msg)
	}
	if len(b.pending) >= InboxPendingCap {
		b.mu.Unlock()
		return fmt.Errorf("%s: inbox pending full (%d)", b.label, InboxPendingCap)
	}
	key := inboxWireKey(senderNodeID, wireB64)
	for _, p := range b.pending {
		if p.wireKey == key {
			b.mu.Unlock()
			return nil
		}
	}
	b.pending = append(b.pending, inboxPending{
		senderNodeID: senderNodeID,
		wireKey:      key,
		module:       mod,
		msg:          msg,
	})
	b.mu.Unlock()
	return nil
}
