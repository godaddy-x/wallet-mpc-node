package mobile

import (
	"fmt"
	"os"
	"strings"

	"github.com/godaddy-x/freego/core/str"
	"github.com/godaddy-x/wallet-mpc-node/connect"
)

const (
	envNodeClientPrk = "MPC_NODE_CLIENT_PRK"
	envKeystoreKey   = "MPC_KEYSTORE_KEY"
)

type mobileNodeSecrets struct {
	keystoreKey string
	clientPrk   string
}

// diskNodeConfig is the on-disk mobile cli_node.json shape (prod example; no secrets).
type diskNodeConfig struct {
	Domain       string `json:"domain"`
	KeyPath      string `json:"keyPath"`
	LoginPath    string `json:"loginPath"`
	Source       string `json:"source"`
	AppID        string `json:"appID,omitempty"`
	AppKey       string `json:"appKey,omitempty"`
	ServerPub    string `json:"serverPub"`
	ClientNo     int64  `json:"clientNo"`
	TokenExp     int64  `json:"tokenExp,omitempty"`
	BroadcastKey string `json:"broadcastKey"`
	ShardKeysDir string `json:"shardKeysDir,omitempty"`
}

func toDiskNodeConfig(cfg connect.SdkConfig) diskNodeConfig {
	return diskNodeConfig{
		Domain:       cfg.Domain,
		KeyPath:      cfg.KeyPath,
		LoginPath:    cfg.LoginPath,
		Source:       cfg.Source,
		AppID:        cfg.AppID,
		AppKey:       cfg.AppKey,
		ServerPub:    cfg.ServerPub,
		ClientNo:     cfg.ClientNo,
		TokenExp:     cfg.TokenExp,
		BroadcastKey: cfg.BroadcastKey,
		ShardKeysDir: cfg.ShardKeysDir,
	}
}

// prepareMobileNodeConfig parses inbound JSON, extracts secrets for env injection,
// and returns on-disk JSON without keystoreKey / clientPrk (prod cli_node shape).
func prepareMobileNodeConfig(configJSON string) (redactedJSON []byte, secrets mobileNodeSecrets, err error) {
	raw := strings.TrimSpace(configJSON)
	if raw == "" {
		return nil, mobileNodeSecrets{}, fmt.Errorf("configJSON is required")
	}

	cfg := connect.SdkConfig{}
	if err := utils.JsonUnmarshal(utils.Str2Bytes(raw), &cfg); err != nil {
		return nil, mobileNodeSecrets{}, fmt.Errorf("invalid configJSON: %w", err)
	}

	secrets = mobileNodeSecrets{
		keystoreKey: strings.TrimSpace(cfg.KeystoreKey),
		clientPrk:   strings.TrimSpace(cfg.ClientPrk),
	}

	redactedJSON, err = utils.JsonMarshal(toDiskNodeConfig(cfg))
	if err != nil {
		return nil, mobileNodeSecrets{}, fmt.Errorf("marshal redacted config: %w", err)
	}
	return redactedJSON, secrets, nil
}

// applyMobileNodeSecrets injects secrets for config.LoadNodeConfigFile env overlays.
// Values are kept in process memory only; cli_node.json on disk stays redacted.
func applyMobileNodeSecrets(secrets mobileNodeSecrets) {
	if secrets.keystoreKey != "" {
		_ = os.Setenv(envKeystoreKey, secrets.keystoreKey)
	}
	if secrets.clientPrk != "" {
		_ = os.Setenv(envNodeClientPrk, secrets.clientPrk)
	}
}

func clearMobileNodeSecrets() {
	_ = os.Unsetenv(envKeystoreKey)
	_ = os.Unsetenv(envNodeClientPrk)
}
