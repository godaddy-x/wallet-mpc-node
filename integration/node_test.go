package integration

import (
	"testing"

	"github.com/godaddy-x/wallet-mpc-node/internal/app"
)

func TestRunNode0(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node0.json")
	select {}
}

func TestRunNode1(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node1.json")
	select {}
}

func TestRunNode2(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node2.json")
	select {}
}
