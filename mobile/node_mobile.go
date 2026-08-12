// Package mobile exposes wallet-mpc-node for gomobile (Android/iOS).
package mobile

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/godaddy-x/wallet-mpc-node/internal/app"
)

var (
	mu      sync.Mutex
	running bool
	stopFn  func()
	epoch   uint64 // bumped on Stop / supersede so in-flight Start cannot resurrect a stopped node
)

// Version returns the mobile binding version string.
func Version() string {
	return "0.1.1-mobile"
}

// StartNode launches the MPC node in a background goroutine.
// configJSON may include keystoreKey and clientPrk for in-memory env injection;
// the on-disk cli_node.json is written without those fields (prod shape).
// dataDir is the app sandbox directory (config file and shard keys under dataDir).
// Returns empty string on success, or an error message.
// If a node is already running, returns empty string (no-op). Call StopNode first to restart.
func StartNode(configJSON string, dataDir string) string {
	mu.Lock()
	if running {
		mu.Unlock()
		return ""
	}
	if configJSON == "" {
		mu.Unlock()
		return "configJSON is required"
	}
	if dataDir == "" {
		mu.Unlock()
		return "dataDir is required"
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		mu.Unlock()
		return err.Error()
	}
	redactedJSON, secrets, err := prepareMobileNodeConfig(configJSON)
	if err != nil {
		mu.Unlock()
		return err.Error()
	}
	cfgPath := filepath.Join(dataDir, "cli_node.json")
	if err := os.WriteFile(cfgPath, redactedJSON, 0o600); err != nil {
		mu.Unlock()
		return err.Error()
	}
	applyMobileNodeSecrets(secrets)
	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		mu.Unlock()
		return err.Error()
	}

	running = true
	myEpoch := epoch
	mu.Unlock()

	go func() {
		_, stop, err := app.LaunchMPCNode(cfgPath, "info", true, dataDir, keysDir)

		mu.Lock()
		defer mu.Unlock()
		// StopNode (or a newer Start after stop) happened while we were launching.
		if myEpoch != epoch {
			if stop != nil {
				go stop()
			}
			return
		}
		if err != nil {
			running = false
			stopFn = nil
			return
		}
		stopFn = stop
		running = true
	}()
	return ""
}

// IsRunning reports whether StartNode was called and the node has not been stopped / failed.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// StopNode closes the broker WebSocket client and stops reconnect loops.
func StopNode() {
	mu.Lock()
	epoch++
	stop := stopFn
	stopFn = nil
	running = false
	mu.Unlock()
	clearMobileNodeSecrets()
	if stop != nil {
		stop()
	}
}
