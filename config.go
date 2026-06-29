// 节点部署配置：JSON 读取 + TEE env 注入（node 专属，不进入 sdkconfig / walletapi）。
package main

import (
	"fmt"
	"strings"

	"github.com/godaddy-x/freego/utils/envoverlay"
	"github.com/godaddy-x/wallet-mpc-node/connect"
)

// nodeEnvSecrets 节点 TEE 注入项（env 非空则覆盖 JSON 原值）。
const (
	envNodeClientPrk = "MPC_NODE_CLIENT_PRK"
	envKeystoreKey   = "MPC_KEYSTORE_KEY"
)

func applyNodeEnvOverrides(cfg *connect.SdkConfig) {
	if cfg == nil {
		return
	}
	envoverlay.OverrideString(&cfg.ClientPrk, envNodeClientPrk)
	envoverlay.OverrideString(&cfg.KeystoreKey, envKeystoreKey)
}

func loadNodeConfigFile(path string) (connect.SdkConfig, error) {
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
