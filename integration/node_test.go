package integration

import (
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/godaddy-x/wallet-mpc-node/internal/app"
)

// blockUntilStop waits for IDE stop / Ctrl+C instead of select{}.
// go test on Windows often leaves the compiled .test.exe child running when only
// the parent "go test" process is killed; handling Interrupt lets Stop work when
// the signal reaches this process.
func blockUntilStop(t *testing.T) {
	t.Helper()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	sig := <-ch
	signal.Stop(ch)
	t.Logf("node stop signal: %v", sig)
}

func TestRunNode0(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node0.json")
	blockUntilStop(t)
}

func TestRunNode1(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node1.json")
	blockUntilStop(t)
}

func TestRunNode2(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node2.json")
	blockUntilStop(t)
}

func TestRunNode3(t *testing.T) {
	app.LaunchMPCNodeForTest("cli_node3.json")
	blockUntilStop(t)
}
