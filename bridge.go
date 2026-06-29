package main

import (
	"sync"

	sirLog "github.com/getamis/sirius/log"
	"github.com/godaddy-x/freego/zlog"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
)

var (
	aliceLogBridgeOnce sync.Once
	aliceLogBridgePrev sirLog.Handler
)

// enableAliceProtocolTrace 将 Alice/sirius 的 Warn+ 日志桥接到 zlog，并写入 alg_ecdsa 失败追踪。
func enableAliceProtocolTrace() {
	aliceLogBridgeOnce.Do(func() {
		bridge := sirLog.New("mpc-alice")
		aliceLogBridgePrev = bridge.GetHandler()
		bridge.SetHandler(sirLog.FuncHandler(func(r *sirLog.Record) error {
			if r.Lvl <= sirLog.LvlWarn {
				mpc.RecordAliceProtocolLog(r.Msg, r.Ctx)
				zlog.Warn("[alice] "+r.Msg, 0)
			}
			if aliceLogBridgePrev != nil {
				return aliceLogBridgePrev.Log(r)
			}
			return nil
		}))
	})
}
