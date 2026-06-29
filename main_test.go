package main

import (
	"testing"
)

func TestRunNode0(t *testing.T) {
	LaunchMPCNodeForTest("cli_node0.json")
	select {}
}

func TestRunNode1(t *testing.T) {
	LaunchMPCNodeForTest("cli_node1.json")
	select {}
}

func TestRunNode2(t *testing.T) {
	LaunchMPCNodeForTest("cli_node2.json")
	select {}
}
