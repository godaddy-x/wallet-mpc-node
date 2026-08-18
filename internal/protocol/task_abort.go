// task_abort.go：MPC 任务快速失败 — 统一 abort 入口（Push mpcTaskAbort + 业务 JWT WS 断开）。
package protocol

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/godaddy-x/freego/client/ws"
	utils "github.com/godaddy-x/freego/core/str"
	"github.com/godaddy-x/wallet-mpc-node/internal/config"
	"github.com/godaddy-x/wallet-mpc-node/internal/log"
	"github.com/godaddy-x/wallet-mpc-node/internal/tempkey"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ecdsa"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ed25519"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_single"
	"github.com/godaddy-x/wallet-mpc-node/types"
)

const (
	mpcAbortedTaskTTL = 15 * time.Minute
	lastGaspErrMsg    = "broker_ws_disconnected"
)

var (
	abortedTasksMu sync.Mutex
	abortedTasks   = make(map[string]time.Time) // taskID -> aborted at
)

// tryMarkTaskAborted 原子标记；返回 false 表示已 abort（幂等）。
func tryMarkTaskAborted(taskID string) bool {
	if taskID == "" {
		return false
	}
	now := time.Now()
	abortedTasksMu.Lock()
	defer abortedTasksMu.Unlock()
	pruneAbortedTasksLocked(now)
	if at, ok := abortedTasks[taskID]; ok && now.Sub(at) <= mpcAbortedTaskTTL {
		return false
	}
	abortedTasks[taskID] = now
	return true
}

func isTaskAborted(taskID string) bool {
	if taskID == "" {
		return false
	}
	now := time.Now()
	abortedTasksMu.Lock()
	defer abortedTasksMu.Unlock()
	pruneAbortedTasksLocked(now)
	at, ok := abortedTasks[taskID]
	return ok && now.Sub(at) <= mpcAbortedTaskTTL
}

func pruneAbortedTasksLocked(now time.Time) {
	for id, at := range abortedTasks {
		if now.Sub(at) > mpcAbortedTaskTTL {
			delete(abortedTasks, id)
		}
	}
}

// startingTasks：Handle*Start 已解析 taskID、尚未 register session 的窗口。
// OnBrokerWsDisconnected 必须扫到这些 task，否则断线只打标不到 session。
var (
	startingTasksMu sync.Mutex
	startingTasks   = make(map[string]struct{}) // taskID|nodeID
)

func noteStartingTask(taskID, nodeID string) {
	if taskID == "" || nodeID == "" {
		return
	}
	startingTasksMu.Lock()
	startingTasks[taskID+"|"+nodeID] = struct{}{}
	startingTasksMu.Unlock()
}

func clearStartingTask(taskID, nodeID string) {
	if taskID == "" || nodeID == "" {
		return
	}
	startingTasksMu.Lock()
	delete(startingTasks, taskID+"|"+nodeID)
	startingTasksMu.Unlock()
}

func listStartingTaskIDs(nodeID string) []string {
	suffix := "|" + nodeID
	startingTasksMu.Lock()
	defer startingTasksMu.Unlock()
	out := make([]string, 0)
	for key := range startingTasks {
		if strings.HasSuffix(key, suffix) {
			out = append(out, key[:len(key)-len(suffix)])
		}
	}
	return out
}

// stopIfTaskAborted 供 Start handler 在 begin/register 之后调用。
// abort 可能已 tryMark（当时尚无 session），此处补 cancel 刚注册的 abortCtx。
func stopIfTaskAborted(wsClient *ws.SDK, myNodeID, taskID, kind string) error {
	if !isTaskAborted(taskID) {
		return nil
	}
	abortTaskSession(wsClient, myNodeID, taskID, "task_aborted", false)
	if kind == "sign" {
		return errors.New("sign task aborted")
	}
	return errors.New("keygen task aborted")
}

func protocolCtx(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

func keygenProtocolCtx(s *keygenSession, timeout time.Duration) (context.Context, context.CancelFunc) {
	var parent context.Context
	if s != nil && s.abortCtx != nil {
		parent = s.abortCtx
	}
	return protocolCtx(parent, timeout)
}

func signProtocolCtx(s *signSession, timeout time.Duration) (context.Context, context.CancelFunc) {
	var parent context.Context
	if s != nil && s.abortCtx != nil {
		parent = s.abortCtx
	}
	return protocolCtx(parent, timeout)
}

// checkSessionAborted 统一 abortCtx 与全局 aborted 标记检查。
func checkSessionAborted(abortCtx context.Context, taskID string) error {
	if abortCtx != nil {
		if err := abortCtx.Err(); err != nil {
			return err
		}
	}
	if isTaskAborted(taskID) {
		return errors.New("task aborted")
	}
	return nil
}

func clearEarlyKeygenMessages(taskID, nodeID string) {
	key := keygenSessionKey(taskID, nodeID)
	earlyKeygenMessagesMu.Lock()
	delete(earlyKeygenMessages, key)
	earlyKeygenMessagesMu.Unlock()
}

func clearEarlySignMessages(taskID, nodeID string) {
	key := signSessionKey(taskID, nodeID)
	earlySignMessagesMu.Lock()
	delete(earlySignMessages, key)
	earlySignMessagesMu.Unlock()
}

func listActiveKeygenTaskIDs(nodeID string) []string {
	suffix := "|" + nodeID
	keygenSessionsMu.RLock()
	defer keygenSessionsMu.RUnlock()
	out := make([]string, 0)
	for key := range keygenSessions {
		if strings.HasSuffix(key, suffix) {
			out = append(out, key[:len(key)-len(suffix)])
		}
	}
	return out
}

func listActiveSignTaskIDs(nodeID string) []string {
	suffix := "|" + nodeID
	signSessionsMu.RLock()
	defer signSessionsMu.RUnlock()
	out := make([]string, 0)
	for key := range signSessions {
		if strings.HasSuffix(key, suffix) {
			out = append(out, key[:len(key)-len(suffix)])
		}
	}
	return out
}

// deleteUnconfirmedKeygenShare 若本 task 已 Save 分片，尽力按 SessionID=taskID 删除。
func deleteUnconfirmedKeygenShare(taskID, nodeID, keyID string) {
	if taskID == "" || nodeID == "" || keyID == "" {
		return
	}
	base := config.ShardKeysDir()

	if store := alg_ecdsa.NewFileKeyStore(base); store != nil {
		if data, err := store.Load(keyID, nodeID); err == nil && data != nil && data.SessionID == taskID {
			if err := store.Delete(keyID, nodeID); err != nil {
				log.Keygenf("abort delete ecdsa share failed task=%s keyID=%s err=%v\n", taskID, keyID, err)
			} else {
				log.Keygenf("abort deleted ecdsa share task=%s keyID=%s\n", taskID, keyID)
			}
			return
		}
	}
	if store := alg_ed25519.NewFileKeyStore(base); store != nil {
		if data, err := store.Load(keyID, nodeID); err == nil && data != nil && data.SessionID == taskID {
			if err := store.Delete(keyID, nodeID); err != nil {
				log.Keygenf("abort delete frost share failed task=%s keyID=%s err=%v\n", taskID, keyID, err)
			} else {
				log.Keygenf("abort deleted frost share task=%s keyID=%s\n", taskID, keyID)
			}
			return
		}
	}
	if store := alg_single.NewFileKeyStore(base); store != nil {
		if data, err := store.Load(keyID, nodeID); err == nil && data != nil && data.SessionID == taskID {
			if err := store.Delete(keyID, nodeID); err != nil {
				log.Keygenf("abort delete single key failed task=%s keyID=%s err=%v\n", taskID, keyID, err)
			} else {
				log.Keygenf("abort deleted single key task=%s keyID=%s\n", taskID, keyID)
			}
		}
	}
}

func abortKeygenSession(wsClient *ws.SDK, myNodeID, taskID string, s *keygenSession, reason string, lastGasp bool) {
	if s == nil || s.isClosed() {
		return
	}
	if s.abortCancel != nil {
		s.abortCancel()
	}
	abortErr := errors.New(reason)
	select {
	case s.errCh <- abortErr:
	default:
	}
	persisted := s.takePersistedKey()
	s.close()
	unregisterKeygenSession(taskID, myNodeID, s)
	endKeygenTask(taskID, myNodeID)
	clearEarlyKeygenMessages(taskID, myNodeID)
	if len(s.nodeIDs) > 0 {
		tempkey.ClearKeygenSessionKeys(myNodeID, taskID, s.nodeIDs)
	}
	deleteUnconfirmedKeygenShare(taskID, myNodeID, persisted)
	// freego 在清 conn 前同步回调时仍可写；勿依赖 IsWebSocketConnected。
	if lastGasp && wsClient != nil {
		_ = submitKeygenResultLastGasp(wsClient, taskID, myNodeID, lastGaspErrMsg)
	}
	log.Keygenf("abortKeygenSession: task=%s node=%s reason=%s lastGasp=%t\n", taskID, myNodeID, reason, lastGasp)
}

func abortSignSession(wsClient *ws.SDK, myNodeID, taskID string, s *signSession, reason string, lastGasp bool) {
	if s == nil || s.isClosed() {
		return
	}
	if s.alice != nil && s.keyID != "" {
		cancelPriorEcdsaWarm(ecdsaWarmSessionKey(s.keyID, s.alice.sortedIDs))
	}
	if s.abortCancel != nil {
		s.abortCancel()
	}
	abortErr := errors.New(reason)
	select {
	case s.errCh <- abortErr:
	default:
	}
	s.close()
	unregisterSignSession(taskID, myNodeID, s)
	endSignTask(taskID, myNodeID)
	clearEarlySignMessages(taskID, myNodeID)
	if len(s.allNodeIDs) > 0 {
		tempkey.ClearSignSessionKeys(myNodeID, taskID, s.allNodeIDs)
	}
	if lastGasp && wsClient != nil {
		req := &types.CliMPCSignResultReq{
			TaskID: taskID,
			NodeID: myNodeID,
			KeyID:  s.keyID,
			Err:    lastGaspErrMsg,
		}
		var res types.CliMPCSignResultRes
		_ = wsClient.SendWebSocketMessage("/ws/mpcSignResult", req, &res, true, true, 3)
	}
	log.SignErrf("TRACE_NODE_SIGN_ABORT task=%s node=%s reason=%s lastGasp=%t", taskID, myNodeID, reason, lastGasp)
}

// abortTaskSession 幂等终止指定 task 的本地会话（Push 与 WS 断开共用）。
// 已标记 aborted 仍须查找 session：Abort 可能发生在 register 之前，Start 随后才挂上 session。
func abortTaskSession(wsClient *ws.SDK, myNodeID, taskID, reason string, lastGasp bool) {
	if taskID == "" {
		return
	}
	first := tryMarkTaskAborted(taskID)
	if reason == "" {
		reason = "task_aborted"
	}
	doGasp := lastGasp && first
	if s := getKeygenSession(taskID, myNodeID); s != nil {
		abortKeygenSession(wsClient, myNodeID, taskID, s, reason, doGasp)
		return
	}
	if s := getSignSession(taskID, myNodeID); s != nil {
		abortSignSession(wsClient, myNodeID, taskID, s, reason, doGasp)
		return
	}
	if doGasp && wsClient != nil {
		_ = submitKeygenResultLastGasp(wsClient, taskID, myNodeID, lastGaspErrMsg)
		req := &types.CliMPCSignResultReq{TaskID: taskID, NodeID: myNodeID, Err: lastGaspErrMsg}
		var res types.CliMPCSignResultRes
		_ = wsClient.SendWebSocketMessage("/ws/mpcSignResult", req, &res, true, true, 3)
	}
}

// OnBrokerWsDisconnected 业务 JWT WS 断开：终止本机全部活跃/正在 Start 的 keygen/sign，并尽力 last-gasp。
func OnBrokerWsDisconnected(wsClient *ws.SDK, myNodeID string) {
	seen := make(map[string]struct{})
	for _, src := range [][]string{
		listStartingTaskIDs(myNodeID),
		listActiveKeygenTaskIDs(myNodeID),
		listActiveSignTaskIDs(myNodeID),
	} {
		for _, taskID := range src {
			if taskID == "" {
				continue
			}
			seen[taskID] = struct{}{}
		}
	}
	for taskID := range seen {
		abortTaskSession(wsClient, myNodeID, taskID, lastGaspErrMsg, true)
	}
}

// HandleMpcTaskAbort 处理 broker 推送的 mpcTaskAbort（不再 last-gasp）。
func HandleMpcTaskAbort(wsClient *ws.SDK, myNodeID string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var payload types.CliMPCTaskAbortRes
	if err := utils.JsonUnmarshal(body, &payload); err != nil {
		return err
	}
	reason := strings.TrimSpace(payload.Reason)
	if reason == "" {
		reason = "task_aborted"
	}
	abortTaskSession(wsClient, myNodeID, payload.TaskID, reason, false)
	return nil
}
