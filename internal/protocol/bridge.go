package protocol

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
