package protocol

import (
	"testing"

	"github.com/godaddy-x/wallet-mpc-node/types"
)

func TestIsSingleKeygenStart(t *testing.T) {
	if !isSingleKeygenStart(types.CliMPCKeygenStartRes{Threshold: 1, NodeIDs: []string{"node0"}}) {
		t.Fatal("expected single keygen")
	}
	if isSingleKeygenStart(types.CliMPCKeygenStartRes{Threshold: 1, NodeIDs: []string{"a", "b", "c"}}) {
		t.Fatal("threshold=1 with 3 nodes must not be single keygen")
	}
	if isSingleKeygenStart(types.CliMPCKeygenStartRes{Threshold: 2, NodeIDs: []string{"node0"}}) {
		t.Fatal("threshold=2 must not be single keygen")
	}
}

func TestIsSingleSignStart(t *testing.T) {
	if !isSingleSignStart(types.CliMPCSignStartRes{
		Threshold:   1,
		SignNodeIDs: []string{"node0"},
		AllNodeIDs:  []string{"node0"},
	}) {
		t.Fatal("expected single sign")
	}
	if !isSingleSignStart(types.CliMPCSignStartRes{
		Threshold:   1,
		SignNodeIDs: []string{"node0"},
	}) {
		t.Fatal("expected single sign when allNodeIDs omitted")
	}
	if isSingleSignStart(types.CliMPCSignStartRes{
		Threshold:   1,
		SignNodeIDs: []string{"node0"},
		AllNodeIDs:  []string{"node0", "node1", "node2"},
	}) {
		t.Fatal("1-of-3 mpc wallet must not use single sign path")
	}
	if isSingleSignStart(types.CliMPCSignStartRes{
		Threshold:   1,
		SignNodeIDs: []string{"node0", "node1"},
		AllNodeIDs:  []string{"node0", "node1", "node2"},
	}) {
		t.Fatal("multi-node sign subset must not be single sign")
	}
	if isSingleSignStart(types.CliMPCSignStartRes{
		Threshold:   2,
		SignNodeIDs: []string{"node0", "node1"},
		AllNodeIDs:  []string{"node0", "node1", "node2"},
	}) {
		t.Fatal("threshold=2 must not be single sign")
	}
}
