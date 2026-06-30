// 节点程序入口：连接服务端 WebSocket，处理临时公钥交换与 mpcKeygen/mpcSign 的 Push 与 POST，参与 TSS 协议。
package main

import (
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/cache"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/freego/zlog"
	"github.com/godaddy-x/wallet-mpc-node/connect"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

var (
	keyCache = cache.NewLocalCache()
)

// 节点本地临时 ML-KEM-1024 密钥缓存 TTL（秒），仅依赖 LocalCache 自动过期。
const (
	// 须覆盖服务端一次完整 MPC keygen（约 10 分钟级），略大于 app.mpcKeygenMetaCacheTTLSec。
	keygenTempKeyCacheTTLSeconds = 900 // 15 分钟
	// 须覆盖：sign 公钥收集(~120s) + 节点签名等待(360s) + 余量；私钥在 mpcTempPublicKey 时写入，
	// 若 TTL 过短会在 TSS 中途过期导致无法解密 mpcSignMsg（表现为 recvCount 停涨后 sign timeout）。
	signTempKeyCacheTTLSeconds = 900 // 15 分钟
)

func getTempDecapsKey(mod, subject, taskID string) (*mlkem.DecapsulationKey1024, error) {
	key := utils.FNV1a64(utils.AddStr(subject, ":", taskID, ":", mod, ":tempPrivateKey"))
	value, b, err := keyCache.Get(key, nil)
	if err != nil {
		return nil, err
	}
	if b && value != nil {
		return value.(*mlkem.DecapsulationKey1024), nil
	}
	return nil, nil
}

// submitMpcTempPublicKeyWithRetry 上报临时 ML-KEM-1024 封装公钥；单次请求短超时 + 重试，避免与 sign 协议消息共线时长时间阻塞导致服务端 pubkey 阶段超时。
func submitMpcTempPublicKeyWithRetry(wsClient *sdk.SocketSDK, request *dto.CliMPCTempPublicKeyReq, maxAttempts int) error {
	if wsClient == nil || request == nil {
		return errors.New("submitMpcTempPublicKeyWithRetry invalid argument")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	backoff := []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		var response dto.CliMPCTempPublicKeyRes
		err := wsClient.SendWebSocketMessage("/ws/mpcTempPublicKey", request, &response, true, true, 5)
		if err == nil && response.Success {
			return nil
		}
		if err != nil {
			lastErr = err
		} else if !response.Success {
			lastErr = errors.New("server returned success=false for mpcTempPublicKey")
		}
		if i < maxAttempts {
			sleep := backoff[i-1]
			if i-1 >= len(backoff) {
				sleep = backoff[len(backoff)-1]
			}
			time.Sleep(sleep)
		}
	}
	return lastErr
}

func handleTempPublicKey(wsClient *sdk.SocketSDK, subject, router string, data []byte) error {
	request := dto.CliMPCTempPublicKeyReq{}
	if err := json.Unmarshal(data, &request); err != nil {
		return errors.New("handleTempPublicKey json unmarshal error: " + err.Error())
	}
	if request.Module == "" {
		return errors.New("handleTempPublicKey invalid module")
	}
	var ttl int
	switch request.Module {
	case "keygen":
		ttl = keygenTempKeyCacheTTLSeconds
	case "sign":
		ttl = signTempKeyCacheTTLSeconds
	default:
		return errors.New("handleTempPublicKey invalid module: " + request.Module)
	}
	dk, err := ecc.CreateMLKEM1024()
	if err != nil {
		return errors.New("handleTempPublicKey create ML-KEM-1024 key error: " + err.Error())
	}
	cacheKey := utils.FNV1a64(utils.AddStr(subject, ":", request.TaskID, ":", request.Module, ":tempPrivateKey"))
	if err := keyCache.Put(cacheKey, dk, ttl); err != nil {
		return errors.New("handleTempPublicKey put tempPrivateKey error: " + err.Error())
	}
	request.PublicKey = ecc.MLKEM1024EncapsulationKeyToBase64(dk.EncapsulationKey())
	if err := submitMpcTempPublicKeyWithRetry(wsClient, &request, 3); err != nil {
		return errors.New("handleTempPublicKey submit temp public key error: " + err.Error())
	}
	return nil
}

// refreshTempPrivateKeyTTL 在收到 mpc*Start 后刷新本节点解封装私钥 TTL（私钥在更早的 mpcTempPublicKey 阶段写入）。
func refreshTempPrivateKeyTTL(mod, myNodeID, taskID string, ttlSec int) error {
	key := utils.FNV1a64(utils.AddStr(myNodeID, ":", taskID, ":", mod, ":tempPrivateKey"))
	value, ok, err := keyCache.Get(key, nil)
	if err != nil {
		return err
	}
	if !ok || value == nil {
		return errors.New("temp decaps key missing at " + mod + " start")
	}
	if err := keyCache.Put(key, value, ttlSec); err != nil {
		return fmt.Errorf("refresh tempPrivateKey TTL: %w", err)
	}
	return nil
}

// refreshSignTempPrivateKeyTTL 在收到 mpcSignStart 后刷新本节点 sign 解封装私钥 TTL。
func refreshSignTempPrivateKeyTTL(myNodeID, taskID string) error {
	return refreshTempPrivateKeyTTL("sign", myNodeID, taskID, signTempKeyCacheTTLSeconds)
}

// refreshKeygenTempPrivateKeyTTL 在收到 mpcKeygenStart 后刷新本节点 keygen 解封装私钥 TTL。
func refreshKeygenTempPrivateKeyTTL(myNodeID, taskID string) error {
	return refreshTempPrivateKeyTTL("keygen", myNodeID, taskID, keygenTempKeyCacheTTLSeconds)
}

func nodeLoginAuthToken(cliConfig connect.SdkConfig) (sdk.AuthToken, error) {
	nodeID := strings.TrimSpace(cliConfig.Source)
	if nodeID == "" {
		return sdk.AuthToken{}, errors.New("node config source is empty (e.g. node0)")
	}
	loginSdk := sdk.NewSocketSDK(cliConfig.Domain)
	loginSdk.SetClientNo(cliConfig.ClientNo)
	if err := loginSdk.SetMLDSA87Object(cliConfig.ClientNo, cliConfig.ClientPrk, cliConfig.ServerPub); err != nil {
		return sdk.AuthToken{}, err
	}
	defer loginSdk.DisconnectWebSocket()

	req := &dto.CliPlan2LoginReq{Source: nodeID}
	resp := sdk.AuthToken{}
	keyPath := strings.TrimSpace(cliConfig.KeyPath)
	if keyPath == "" {
		keyPath = "/ws/key"
	}
	loginPath := strings.TrimSpace(cliConfig.LoginPath)
	if loginPath == "" {
		loginPath = "/ws/login"
	}
	if err := loginSdk.LoginByWebSocketPlan2Auto(keyPath, loginPath, req, &resp, 10); err != nil {
		return sdk.AuthToken{}, err
	}
	return resp, nil
}

// tryNodeLogin 尝试 Plan2 登录并写入 JWT；失败仅打日志，由 token 回调与重连协程后续重试。
func tryNodeLogin(wsClient *sdk.SocketSDK, cliConfig connect.SdkConfig) bool {
	auth, err := nodeLoginAuthToken(cliConfig)
	if err != nil {
		zlog.Warn("node login failed", 0, zlog.String("source", cliConfig.Source), zlog.String("errMsg", err.Error()))
		return false
	}
	wsClient.AuthToken(auth)
	return true
}

func RunMPCNode(cliConfig connect.SdkConfig) error {
	wsClient := sdk.NewSocketSDK(cliConfig.Domain)
	wsClient.SetClientNo(cliConfig.ClientNo)
	_ = wsClient.SetMLDSA87Object(cliConfig.ClientNo, cliConfig.ClientPrk, cliConfig.ServerPub)
	wsClient.SetBroadcastKey(cliConfig.BroadcastKey)
	wsClient.EnableReconnect()

	wsClient.SetTokenExpiredCallback(func() {
		tryNodeLogin(wsClient, cliConfig)
	})

	wsClient.SetPushMessageCallback(func(router string, data []byte) {
		if router == "mpcTempPublicKey" {
			if err := handleTempPublicKey(wsClient, cliConfig.Source, router, data); err != nil {
				zlog.Error("mpcTempPublicKey handler", 0, zlog.String("errMsg", err.Error()))
			}
		} else if router == "mpcKeygenStart" {
			go func() {
				if err := HandleMpcKeygenStart(wsClient, cliConfig.Source, router, data); err != nil {
					zlog.Error("mpc keygen start failed", 0, zlog.String("errMsg", err.Error()))
				} else {
					zlog.Info("mpc keygen start accepted", 0, zlog.String("source", cliConfig.Source))
				}
			}()
		} else if router == "mpcKeygenMsg" {
			zlog.Info("Push received", 0, zlog.String("router", router), zlog.String("flow", "keygen"), zlog.Int("len", len(data)))
			if err := DeliverMpcKeygenMsg(wsClient, cliConfig.Source, router, data); err != nil && err.Error() != "Error is nil" {
				zlog.Error("mpcKeygenMsg deliver", 0, zlog.String("errMsg", err.Error()))
			}
		} else if router == "mpcSignStart" {
			go func() {
				if err := HandleMpcSignStart(wsClient, cliConfig.Source, router, data); err != nil {
					zlog.Error("mpc sign start failed", 0, zlog.String("errMsg", err.Error()))
				} else {
					zlog.Info("mpc sign start accepted", 0, zlog.String("source", cliConfig.Source))
				}
			}()
		} else if router == "mpcSignMsg" {
			zlog.Info("Push received", 0, zlog.String("router", router), zlog.String("flow", "sign"), zlog.Int("len", len(data)))
			if err := DeliverMpcSignMsg(wsClient, cliConfig.Source, router, data); err != nil && err.Error() != "Error is nil" {
				zlog.Error("mpcSignMsg deliver", 0, zlog.String("errMsg", err.Error()))
			}
		}
	})

	// 首次登录失败不退出：ConnectWebSocket 会触发 token 回调并在后台重连。
	tryNodeLogin(wsClient, cliConfig)
	wsClient.SetHealthPing(10)

	if err := wsClient.ConnectWebSocket(); err != nil {
		zlog.Error("sdk connect websocket error", 0, zlog.String("errMsg", err.Error()))
		return err
	}

	if wsClient.IsWebSocketConnected() {
		zlog.Info("sdk connect websocket success", 0, zlog.String("source", cliConfig.Source))
	} else {
		zlog.Info("sdk connect websocket pending, async reconnect started", 0, zlog.String("source", cliConfig.Source))
	}

	// 周期性存活日志（仅 debug）：便于区分进程卡死与 WebSocket 假死/断连。
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !zlog.IsDebug() {
				continue
			}
			zlog.Debug("mpc node heartbeat", 0,
				zlog.String("source", cliConfig.Source),
				zlog.Bool("ws_connected", wsClient.IsWebSocketConnected()))
		}
	}()

	return nil
}

// 打包与运行（仓库根目录 wallet-mpc-node）：
//
//	go build -o wallet-mpc-node.exe .
//
//	.\wallet-mpc-node.exe -config cli_node0.json
//	.\wallet-mpc-node.exe -config cli_node0.json -logdir .\logs
//	.\wallet-mpc-node.exe -config cli_node0.json -keysdir .\data\shards
//
// 生产 TEE（私钥不进 JSON，由 env 覆盖，见 examples/cli_node.prod.example.json）：
//
//	set MPC_NODE_CLIENT_PRK=<tee-unsealed>
//	set MPC_KEYSTORE_KEY=<tee-unsealed>
//	.\wallet-mpc-node.exe -config cli_node0.json
//
// 开发直接跑源码（勿使用 go run main.go，需整包编译）：
//
//	go run . -config cli_node0.json
//	go run . -config cli_node0.json -logdir .\logs
//	go run . -config cli_node0.json -keysdir .\keys
func main() {
	run()
}
