// Package broker connects the MPC node to wallet-mpc-broker over WebSocket.
package broker

import (
	"errors"
	"strings"
	"time"

	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/freego/zlog"
	"github.com/godaddy-x/wallet-mpc-node/connect"
	"github.com/godaddy-x/wallet-mpc-node/internal/protocol"
	"github.com/godaddy-x/wallet-mpc-node/internal/tempkey"
	"github.com/godaddy-x/wallet-mpc-node/types"
)

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

	req := &types.CliPlan2LoginReq{Source: nodeID}
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

func tryNodeLogin(wsClient *sdk.SocketSDK, cliConfig connect.SdkConfig) bool {
	auth, err := nodeLoginAuthToken(cliConfig)
	if err != nil {
		zlog.Warn("node login failed", 0, zlog.String("source", cliConfig.Source), zlog.String("errMsg", err.Error()))
		return false
	}
	wsClient.AuthToken(auth)
	return true
}

// Run connects to the broker WebSocket and handles MPC push routes.
func Run(cliConfig connect.SdkConfig) error {
	wsClient := sdk.NewSocketSDK(cliConfig.Domain)
	wsClient.SetClientNo(cliConfig.ClientNo)
	_ = wsClient.SetMLDSA87Object(cliConfig.ClientNo, cliConfig.ClientPrk, cliConfig.ServerPub)
	wsClient.SetBroadcastKey(cliConfig.BroadcastKey)
	wsClient.EnableReconnect()

	wsClient.SetTokenExpiredCallback(func() {
		tryNodeLogin(wsClient, cliConfig)
	})

	wsClient.SetPushMessageCallback(func(router string, data []byte) {
		switch router {
		case "mpcTempPublicKey":
			if err := tempkey.HandleTempPublicKey(wsClient, cliConfig.Source, router, data); err != nil {
				zlog.Error("mpcTempPublicKey handler", 0, zlog.String("errMsg", err.Error()))
			}
		case "mpcKeygenStart":
			go func() {
				if err := protocol.HandleKeygenStart(wsClient, cliConfig.Source, router, data); err != nil {
					zlog.Error("mpc keygen start failed", 0, zlog.String("errMsg", err.Error()))
				} else {
					zlog.Info("mpc keygen start accepted", 0, zlog.String("source", cliConfig.Source))
				}
			}()
		case "mpcKeygenMsg":
			zlog.Info("Push received", 0, zlog.String("router", router), zlog.String("flow", "keygen"), zlog.Int("len", len(data)))
			if err := protocol.DeliverKeygenMsg(wsClient, cliConfig.Source, router, data); err != nil && err.Error() != "Error is nil" {
				zlog.Error("mpcKeygenMsg deliver", 0, zlog.String("errMsg", err.Error()))
			}
		case "mpcSignStart":
			go func() {
				if err := protocol.HandleSignStart(wsClient, cliConfig.Source, router, data); err != nil {
					zlog.Error("mpc sign start failed", 0, zlog.String("errMsg", err.Error()))
				} else {
					zlog.Info("mpc sign start accepted", 0, zlog.String("source", cliConfig.Source))
				}
			}()
		case "mpcSignMsg":
			zlog.Info("Push received", 0, zlog.String("router", router), zlog.String("flow", "sign"), zlog.Int("len", len(data)))
			if err := protocol.DeliverSignMsg(wsClient, cliConfig.Source, router, data); err != nil && err.Error() != "Error is nil" {
				zlog.Error("mpcSignMsg deliver", 0, zlog.String("errMsg", err.Error()))
			}
		}
	})

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
