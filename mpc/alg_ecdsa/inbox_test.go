package alg_ecdsa

import (
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"testing"

	refreshmsg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/getamis/alice/types"
	"google.golang.org/protobuf/proto"
)

func TestInboxBuffersUntilHandlerSet(t *testing.T) {
	inbox := NewInbox()
	raw, err := proto.Marshal(&refreshmsg.Message{
		Id:   "node0",
		Type: refreshmsg.Type_Round1,
		Body: &refreshmsg.Message_Round1{Round1: &refreshmsg.Round1Msg{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wireB64 := mpc.EncodeWire(WireModuleRefresh, raw)

	if err := inbox.Deliver("node0", wireB64); err != nil {
		t.Fatalf("deliver before handler: %v", err)
	}
	if inbox.PendingLen() != 1 {
		t.Fatalf("pending = %d, want 1", inbox.PendingLen())
	}

	var got int
	if err := inbox.SetHandler(func(_ string, msg types.Message) error {
		got++
		if msg.GetId() != "node0" {
			t.Fatalf("msg id = %q", msg.GetId())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
	if inbox.PendingLen() != 0 {
		t.Fatalf("pending after flush = %d", inbox.PendingLen())
	}
}

func TestInboxClearHandlerDropsPending(t *testing.T) {
	inbox := NewInbox()
	raw, err := proto.Marshal(&refreshmsg.Message{
		Id:   "node0",
		Type: refreshmsg.Type_Round1,
		Body: &refreshmsg.Message_Round1{Round1: &refreshmsg.Round1Msg{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wireB64 := mpc.EncodeWire(WireModuleRefresh, raw)
	if err := inbox.Deliver("node0", wireB64); err != nil {
		t.Fatal(err)
	}
	inbox.ClearHandler()
	if inbox.PendingLen() != 0 {
		t.Fatalf("pending after clear = %d", inbox.PendingLen())
	}
}
