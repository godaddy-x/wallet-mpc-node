// Package app bootstraps the MPC node CLI and process lifecycle.
package app

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/godaddy-x/freego/core/crypto"
	"github.com/godaddy-x/wallet-mpc-node/internal/broker"
	"github.com/godaddy-x/wallet-mpc-node/internal/config"
	nodelog "github.com/godaddy-x/wallet-mpc-node/internal/log"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

// LaunchMPCNode loads config, initializes logging/keystore, and connects to the broker.
// stop closes the broker WebSocket client; callers that outlive a single process (mobile) must keep it.
func LaunchMPCNode(configPath, logLevel string, console bool, logDir, keysDirFlag string) (source string, stop func(), err error) {
	cliConfig, err := config.LoadNodeConfigFile(configPath)
	if err != nil {
		return "", nil, err
	}
	config.SetShardKeysDir(config.ResolveShardKeysDir(keysDirFlag, cliConfig.ShardKeysDir))
	if err := config.InitKeystoreEncryption(cliConfig); err != nil {
		return cliConfig.Source, nil, err
	}
	nodelog.InitNodeLog(cliConfig.Source, logLevel, console, logDir)
	stop, err = broker.Run(cliConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node failed to start source=%s: %v\n", cliConfig.Source, err)
	} else {
		fmt.Printf("node started (source=%s, waiting for server if not connected yet)\n", cliConfig.Source)
	}
	return cliConfig.Source, stop, err
}

// LaunchMPCNodeForTest starts a node for integration tests (info log, cwd log dir).
func LaunchMPCNodeForTest(configPath string) {
	wd, err := os.Getwd()
	if err != nil {
		panic("LaunchMPCNodeForTest: cannot get working directory: " + err.Error())
	}
	_, _, _ = LaunchMPCNode(configPath, "info", true, wd, config.DefaultShardKeysDir)
}

// MigrateShardKeysDir encrypts plaintext shards under keysdir and exits.
func MigrateShardKeysDir(configPath, keysDirFlag string) error {
	cliConfig, err := config.LoadNodeConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := config.InitKeystoreEncryption(cliConfig); err != nil {
		return err
	}
	config.SetShardKeysDir(config.ResolveShardKeysDir(keysDirFlag, cliConfig.ShardKeysDir))
	migrated, skipped, err := keystore.MigratePlaintextDir(config.ShardKeysDir())
	if err != nil {
		return err
	}
	fmt.Printf("keystore migrate keysdir=%s migrated=%d skipped=%d\n", config.ShardKeysDir(), migrated, skipped)
	return nil
}

// RunGenKey generates a Plan2 ML-DSA key pair for node provisioning.
func RunGenKey(requireEnc bool, outDir string) (*crypto.Plan2ProvisionResult, error) {
	wrapKey := strings.TrimSpace(os.Getenv(crypto.Plan2WrapKeyEnv))
	if requireEnc && wrapKey == "" {
		return nil, fmt.Errorf("%s is required when -enc is set", crypto.Plan2WrapKeyEnv)
	}
	if wrapKey == "" {
		log.Printf("WARN: genkey: %s not set, writing plaintext private key file", crypto.Plan2WrapKeyEnv)
	}
	key, err := crypto.GeneratePlan2KeyPair()
	if err != nil {
		return nil, err
	}
	result, err := crypto.WritePlan2KeyProvision(outDir, wrapKey, key)
	if err != nil {
		return nil, err
	}
	fmt.Printf("genkey: clientNo=%d\n", result.ClientNo)
	fmt.Printf("genkey: wrote %s %s\n", result.PublicPath(), result.PrivatePath())
	return result, nil
}
