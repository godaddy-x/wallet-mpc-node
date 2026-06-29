// Package sdkconfig 为 walletapi / MPC 节点共用的连接配置（ops.json、cli.json、cli_node*.json）。
// 仅 JSON 读写，不含 TEE/env；部署层（node、app）在加载后自行注入密钥。
package connect

import (
	"github.com/godaddy-x/freego/utils"
)

// SdkConfig 连接钱包服务端所需的 HTTP/WebSocket 与认证参数。
type SdkConfig struct {
	Domain    string `json:"domain"`
	KeyPath   string `json:"keyPath"`
	LoginPath string `json:"loginPath"`
	Source    string `json:"source"`
	AppID     string `json:"appID"`
	AppKey    string `json:"appKey"`
	ClientPrk string `json:"clientPrk"`
	ServerPub string `json:"serverPub"`
	ClientNo  int64  `json:"clientNo"`
	TokenExp  int64  `json:"tokenExp"` // 轮换密钥间隔 单位/秒，最低15秒
	// BroadcastKey 与 WebSocket 服务端 SetPushKeyProvider 返回值一致，用于校验 Code=300 推送签名。
	BroadcastKey string `json:"broadcastKey"`
	// KeystoreKey MPC 分片 at-rest 加密口令（节点进程由 node 包 env 注入）。
	KeystoreKey string `json:"keystoreKey,omitempty"`
	// ShardKeysDir 本节点 MPC 分片落盘目录（{keyID}-nodeN.json）；可被 -keysdir 覆盖。
	ShardKeysDir string `json:"shardKeysDir,omitempty"`
}

// ReadFile 读取 JSON 配置文件，不做 env 覆盖。
func ReadFile(path string) (SdkConfig, error) {
	data, err := utils.ReadFile(path)
	if err != nil {
		return SdkConfig{}, err
	}
	cfg := SdkConfig{}
	if err := utils.JsonUnmarshal(data, &cfg); err != nil {
		return SdkConfig{}, err
	}
	return cfg, nil
}
