// Package config loads node deployment settings and runtime paths.
package config

import (
	"fmt"
	"strings"

	"github.com/godaddy-x/freego/core/envoverlay"
	"github.com/godaddy-x/wallet-mpc-node/connect"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

const DefaultShardKeysDir = "keys"

const (
	envNodeClientPrk = "MPC_NODE_CLIENT_PRK"
	envKeystoreKey   = "MPC_KEYSTORE_KEY"
)

var shardKeysDir = DefaultShardKeysDir

// ShardKeysDir returns the MPC shard keystore directory for this process.
func ShardKeysDir() string {
	return shardKeysDir
}

// SetShardKeysDir sets the MPC shard keystore directory for this process.
func SetShardKeysDir(dir string) {
	if dir != "" {
		shardKeysDir = dir
	} else {
		shardKeysDir = DefaultShardKeysDir
	}
}

func applyNodeEnvOverrides(cfg *connect.SdkConfig) {
	if cfg == nil {
		return
	}
	envoverlay.OverrideString(&cfg.ClientPrk, envNodeClientPrk)
	envoverlay.OverrideString(&cfg.KeystoreKey, envKeystoreKey)
}

// LoadNodeConfigFile reads JSON config, applies TEE env overrides, and validates.
func LoadNodeConfigFile(path string) (connect.SdkConfig, error) {
	cfg, err := connect.ReadFile(path)
	if err != nil {
		return connect.SdkConfig{}, err
	}
	applyNodeEnvOverrides(&cfg)
	if err := validateNodeConfig(cfg); err != nil {
		return connect.SdkConfig{}, err
	}
	return cfg, nil
}

func validateNodeConfig(cfg connect.SdkConfig) error {
	if strings.TrimSpace(cfg.Source) == "" {
		return fmt.Errorf("node config: source is required")
	}
	if strings.TrimSpace(cfg.Domain) == "" {
		return fmt.Errorf("node config: domain is required")
	}
	if strings.TrimSpace(cfg.ServerPub) == "" {
		return fmt.Errorf("node config: serverPub is required")
	}
	if strings.TrimSpace(cfg.ClientPrk) == "" {
		return fmt.Errorf("node config: clientPrk is required (set MPC_NODE_CLIENT_PRK or json clientPrk)")
	}
	if strings.TrimSpace(cfg.BroadcastKey) == "" {
		return fmt.Errorf("node config: broadcastKey is required")
	}
	return nil
}

// ResolveShardKeysDir picks keysdir from CLI flag, JSON, or default.
func ResolveShardKeysDir(flagVal, configVal string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v
	}
	if v := strings.TrimSpace(configVal); v != "" {
		return v
	}
	return DefaultShardKeysDir
}

// InitKeystoreEncryption configures at-rest shard encryption from config/env.
func InitKeystoreEncryption(cfg connect.SdkConfig) error {
	key := strings.TrimSpace(cfg.KeystoreKey)
	if key == "" {
		return fmt.Errorf("MPC_KEYSTORE_KEY or keystoreKey is required (plaintext keystore shards are not supported)")
	}
	keystore.SetEncryptionKey(key)
	return nil
}
