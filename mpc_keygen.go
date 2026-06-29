// 本文件：节点侧 MPC Keygen 处理（HandleMpcKeygenStart、DeliverMpcKeygenMsg、早期消息缓存与 TSS 协议执行）。
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/sdk"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ecdsa"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ed25519"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

// ============ 新增：早期消息缓存 ============
var (
	earlyKeygenMessages   = make(map[string]earlyKeygenBucket) // key = taskID|myNodeID
	earlyKeygenMessagesMu sync.Mutex
	maxEarlyMessages      = mpcTssRecvChBuf // 与 recvCh 同级，避免早期丢关键消息
	earlyMsgTTL           = 15 * time.Minute // 覆盖约 10 分钟 keygen + 余量
)

type earlyKeygenBucket struct {
	items     []recvItem
	createdAt time.Time
}

func cleanupExpiredEarlyKeygenMessagesLocked(now time.Time) {
	for k, b := range earlyKeygenMessages {
		if now.Sub(b.createdAt) > earlyMsgTTL {
			delete(earlyKeygenMessages, k)
		}
	}
}

const keygenMsgDedupLRUSize = 10000

// keygen 协议消息去重：LRU + wire SHA256，与 sign 侧策略一致。
var (
	keygenMsgDedupMu   sync.Mutex
	keygenMsgDedupOnce sync.Once
	keygenMsgDedup     *lru.Cache[string, struct{}]
)

func keygenMsgDedupInit() {
	keygenMsgDedupOnce.Do(func() {
		c, err := lru.New[string, struct{}](keygenMsgDedupLRUSize)
		if err != nil {
			panic("mpc_keygen: dedup LRU init failed: " + err.Error())
		}
		keygenMsgDedup = c
	})
}

func keygenMsgDedupKey(taskID, myNodeID string, fromIndex int, isBroadcast bool, wireB64 string) string {
	sum := sha256.Sum256([]byte(wireB64))
	return fmt.Sprintf("%s|%s|%d|%t|%x", taskID, myNodeID, fromIndex, isBroadcast, sum)
}

func isKeygenMsgDuplicate(taskID, myNodeID string, fromIndex int, isBroadcast bool, wireB64 string) bool {
	keygenMsgDedupInit()
	keygenMsgDedupMu.Lock()
	defer keygenMsgDedupMu.Unlock()
	_, ok := keygenMsgDedup.Get(keygenMsgDedupKey(taskID, myNodeID, fromIndex, isBroadcast, wireB64))
	return ok
}

func markKeygenMsgProcessed(taskID, myNodeID string, fromIndex int, isBroadcast bool, wireB64 string) {
	keygenMsgDedupInit()
	keygenMsgDedupMu.Lock()
	defer keygenMsgDedupMu.Unlock()
	keygenMsgDedup.Add(keygenMsgDedupKey(taskID, myNodeID, fromIndex, isBroadcast, wireB64), struct{}{})
}

func sendKeygenProtocolMsgWithRetry(wsClient *sdk.SocketSDK, req *dto.CliMPCEncryptData, maxAttempts int) error {
	return sendMpcProtocolMsgWithRetry(wsClient, "/ws/mpcKeygenMsg", req, maxAttempts)
}

// ============ 原有类型保持不变 ============
type recvItem struct {
	WireBytes   []byte
	FromIndex   int
	IsBroadcast bool
}

type keygenSession struct {
	router       *wsKeygenRouter
	alice        *wsAliceRouter
	frost        *wsFrostRouter
	recvCh       chan recvItem
	errCh        chan error
	recvCount    uint32
	outSender    *outboundSender
	partyReady   chan struct{} // party.Start() 后通知 delivery 刷新 earlyMsgs
	partyStarted atomic.Bool
	mu           sync.Mutex
	closed       bool
}

func (s *keygenSession) notifyPartyReady() {
	select {
	case s.partyReady <- struct{}{}:
	default:
	}
}

func (s *keygenSession) enqueue(item recvItem) bool {
	return enqueueRecvItem(s.recvCh, &s.closed, &s.mu, func() {
		logKeygenf("Deliver: recvCh full, still waiting fromIndex=%d task=%s\n",
			item.FromIndex, s.router.taskID)
	}, item)
}

func (s *keygenSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.recvCh)
	s.mu.Unlock()
}

// ============ Session 管理（改造 register 函数） ============
var (
	keygenSessions   = make(map[string]*keygenSession)
	keygenSessionsMu sync.RWMutex
	keygenActiveMu   sync.Mutex
	keygenActive     = make(map[string]struct{})
)

func beginKeygenTask(taskID, nodeID string) bool {
	key := keygenSessionKey(taskID, nodeID)
	keygenActiveMu.Lock()
	defer keygenActiveMu.Unlock()
	if _, ok := keygenActive[key]; ok {
		return false
	}
	keygenActive[key] = struct{}{}
	return true
}

func endKeygenTask(taskID, nodeID string) {
	key := keygenSessionKey(taskID, nodeID)
	keygenActiveMu.Lock()
	delete(keygenActive, key)
	keygenActiveMu.Unlock()
}

func keygenSessionKey(taskID, nodeID string) string {
	return taskID + "|" + nodeID
}

// registerKeygenSession now replays early messages
func registerKeygenSession(taskID, nodeID string, s *keygenSession) {
	key := keygenSessionKey(taskID, nodeID)

	// Step 1: 取出并清除该 session 的早期消息
	var replayItems []recvItem
	earlyKeygenMessagesMu.Lock()
	cleanupExpiredEarlyKeygenMessagesLocked(time.Now())
	if b, ok := earlyKeygenMessages[key]; ok {
		replayItems = b.items
		delete(earlyKeygenMessages, key)
	}
	earlyKeygenMessagesMu.Unlock()

	// Step 2: 注册 session（同 key 须关闭旧会话，避免旧 runKeygenDelivery 永不退出）
	keygenSessionsMu.Lock()
	old := keygenSessions[key]
	if old != nil && old != s {
		old.close()
		logKeygenf("registerKeygenSession: replaced stale session task=%s node=%s old=%p new=%p\n",
			taskID, nodeID, old, s)
	}
	keygenSessions[key] = s
	keygenSessionsMu.Unlock()

	// Step 3: 回放早期消息
	for _, item := range replayItems {
		if !s.enqueue(item) {
			logKeygenf("replay early msg failed (session closed) task=%s node=%s\n", taskID, nodeID)
		} else {
			logKeygenf("replayed early msg task=%s node=%s fromIndex=%d\n", taskID, nodeID, item.FromIndex)
		}
	}
}

// unregisterKeygenSession 仅当 map 中仍是本指针时删除，避免旧 goroutine 晚结束误删新会话。
func unregisterKeygenSession(taskID, nodeID string, s *keygenSession) bool {
	key := keygenSessionKey(taskID, nodeID)

	keygenSessionsMu.Lock()
	cur := keygenSessions[key]
	if cur != s {
		keygenSessionsMu.Unlock()
		logKeygenf("unregisterKeygenSession: stale skip task=%s node=%s want=%p cur=%p\n",
			taskID, nodeID, s, cur)
		return false
	}
	delete(keygenSessions, key)
	keygenSessionsMu.Unlock()

	earlyKeygenMessagesMu.Lock()
	delete(earlyKeygenMessages, key)
	earlyKeygenMessagesMu.Unlock()
	return true
}

func (s *keygenSession) finishKeygenOutbound(closeOutCh func()) error {
	if closeOutCh != nil {
		closeOutCh()
	}
	sender := s.outSender
	s.close()
	drainOutSender(sender)
	if sender != nil {
		return sender.FirstSendErr()
	}
	return nil
}

func getKeygenSession(taskID, nodeID string) *keygenSession {
	keygenSessionsMu.RLock()
	defer keygenSessionsMu.RUnlock()
	return keygenSessions[keygenSessionKey(taskID, nodeID)]
}

// ============ 消息投递逻辑（不变） ============
func runKeygenDelivery(s *keygenSession) {
	logKeygenf("task=%s myIndex=%d delivery goroutine started\n", s.router.taskID, s.router.myIndex)

	var earlyMsgs []recvItem

	flushEarly := func(trigger *recvItem) {
		if !s.partyStarted.Load() {
			if trigger != nil {
				if len(earlyMsgs) < maxEarlyMessages {
					earlyMsgs = append(earlyMsgs, *trigger)
					logKeygenf("task=%s cached early msg fromIndex=%d (total=%d)\n",
						s.router.taskID, trigger.FromIndex, len(earlyMsgs))
				} else {
					logKeygenf("task=%s dropped early msg (buffer full) fromIndex=%d\n",
						s.router.taskID, trigger.FromIndex)
				}
			}
			return
		}
		if n := len(earlyMsgs); n > 0 {
			logKeygenf("task=%s flushing %d early msgs (party ready)\n", s.router.taskID, n)
			for _, early := range earlyMsgs {
				processMessage(s, early)
			}
			earlyMsgs = nil
		}
		if trigger != nil {
			processMessage(s, *trigger)
		}
	}

	for {
		select {
		case item, ok := <-s.recvCh:
			if !ok {
				return
			}
			if item.FromIndex == s.router.myIndex {
				continue
			}
			flushEarly(&item)
		case <-s.partyReady:
			flushEarly(nil)
		}
	}
}

func processMessage(s *keygenSession, item recvItem) {
	wireB64 := base64.StdEncoding.EncodeToString(item.WireBytes)
	if isKeygenMsgDuplicate(s.router.taskID, s.router.subject, item.FromIndex, item.IsBroadcast, wireB64) {
		logKeygenf("Deliver: dedup skip at process task=%s node=%s fromIndex=%d\n",
			s.router.taskID, s.router.subject, item.FromIndex)
		return
	}
	var err error
	if s.frost != nil {
		err = s.frost.Receive(item.FromIndex, item.WireBytes)
	} else if s.alice != nil {
		err = s.alice.Receive(item.FromIndex, item.WireBytes)
	} else {
		err = fmt.Errorf("keygen session missing wire router")
	}
	if err != nil && err.Error() != "Error is nil" {
		deliverSessionErr(s.errCh, err)
		return
	}
	markKeygenMsgProcessed(s.router.taskID, s.router.subject, item.FromIndex, item.IsBroadcast, wireB64)
	atomic.AddUint32(&s.recvCount, 1)
}

// ============ DeliverMpcKeygenMsg（改造：支持缓存早期消息） ============
func DeliverMpcKeygenMsg(wsClient *sdk.SocketSDK, myNodeID, router string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var decrypt dto.CliMPCEncryptData
	if err := utils.JsonUnmarshal(body, &decrypt); err != nil {
		return err
	}
	prk, err := getTempDecapsKey("keygen", myNodeID, decrypt.TaskID)
	if err != nil {
		return err
	}
	if prk == nil {
		return errors.New("temp decaps key is nil")
	}
	msg, err := ecc.DecryptMLKEM1024(prk, utils.Base64Decode(decrypt.Data), utils.Str2Bytes(utils.AddStr(decrypt.TaskID, "|", myNodeID, "|mpcKeygenMsg")), nil)
	if err != nil {
		return err
	}
	var res dto.CliMPCKeygenMsgRes
	if err := utils.JsonUnmarshal(msg, &res); err != nil {
		logKeygenf("Deliver: json error = %v\n", err)
		return err
	}

	taskID := res.TaskID
	sessionKey := keygenSessionKey(taskID, myNodeID)

	s := getKeygenSession(taskID, myNodeID)
	if s == nil {
		// ❗ Session 不存在：缓存为早期消息
		wireBytes, err := base64.StdEncoding.DecodeString(res.WireBytesBase64)
		if err != nil {
			logKeygenf("Deliver: base64 decode error = %v\n", err)
			return err
		}

		earlyKeygenMessagesMu.Lock()
		now := time.Now()
		cleanupExpiredEarlyKeygenMessagesLocked(now)
		if b, exists := earlyKeygenMessages[sessionKey]; exists && len(b.items) >= maxEarlyMessages {
			earlyKeygenMessagesMu.Unlock()
			logKeygenf("Deliver: dropped early msg (buffer full) task=%s node=%s\n", taskID, myNodeID)
			return nil
		}
		item := recvItem{
			WireBytes:   wireBytes,
			FromIndex:   res.FromIndex,
			IsBroadcast: res.IsBroadcast,
		}
		b := earlyKeygenMessages[sessionKey]
		if b.createdAt.IsZero() {
			b.createdAt = now
		}
		b.items = append(b.items, item)
		earlyKeygenMessages[sessionKey] = b
		earlyKeygenMessagesMu.Unlock()

		logKeygenf("Deliver: cached early msg task=%s node=%s fromIndex=%d\n", taskID, myNodeID, res.FromIndex)
		return nil
	}

	// 己方消息不处理
	if res.FromIndex == s.router.myIndex {
		logKeygenf("Deliver: dropped (own) task=%s myIndex=%d fromIndex=%d\n",
			taskID, s.router.myIndex, res.FromIndex)
		return nil
	}

	wireBytes, err := base64.StdEncoding.DecodeString(res.WireBytesBase64)
	if err != nil {
		logKeygenf("Deliver: base64 error = %v\n", err)
		return err
	}
	item := recvItem{
		WireBytes:   wireBytes,
		FromIndex:   res.FromIndex,
		IsBroadcast: res.IsBroadcast,
	}
	if !s.enqueue(item) {
		logKeygenf("Deliver: session already closed for task %s\n", taskID)
		return nil
	}
	logKeygenf("Deliver: enqueued myIndex=%d fromIndex=%d task=%s\n", s.router.myIndex, res.FromIndex, taskID)
	return nil
}

// ============ 以下是你原有的业务逻辑（未改动，仅保留上下文） ============

// RunKeygenNodeRealByAlg 按算法运行一次本节点的 keygen 协议（CGGMP / Alice）。
func RunKeygenNodeRealByAlg(start dto.CliMPCKeygenStartRes, myNodeID string, wsClient *sdk.SocketSDK, session *keygenSession) (keyID string, err error) {
	switch mpc.Algorithm(start.Algorithm) {
	case mpc.AlgECDSA:
		return runKeygenNodeECDSA(start, myNodeID, wsClient, session)
	case mpc.AlgEd25519:
		return runKeygenNodeFROST(start, myNodeID, wsClient, session)
	default:
		return "", fmt.Errorf("unsupported MPC algorithm for keygen on node: %s", start.Algorithm)
	}
}

func submitKeygenResultWithRetry(wsClient *sdk.SocketSDK, req *dto.CliMPCKeygenResultReq, maxAttempts int) error {
	if wsClient == nil || req == nil {
		return errors.New("submitKeygenResultWithRetry invalid argument")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	backoff := []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		var res dto.CliMPCKeygenResultRes
		err := wsClient.SendWebSocketMessage("/ws/mpcKeygenResult", req, &res, true, true, 30)
		if err == nil && res.OK {
			return nil
		}
		if err != nil {
			lastErr = err
		} else if !res.OK {
			lastErr = errors.New("server rejected result: " + res.Err)
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

const maxErrMsgLen = 256

func submitKeygenResultErr(wsClient *sdk.SocketSDK, taskID, nodeID, errMsg string) error {
	if len(errMsg) > maxErrMsgLen {
		errMsg = errMsg[:maxErrMsgLen] + "..."
	}
	req := &dto.CliMPCKeygenResultReq{
		TaskID: taskID,
		NodeID: nodeID,
		Err:    errMsg,
	}
	_ = submitKeygenResultWithRetry(wsClient, req, 3)
	return nil
}

func HandleMpcKeygenStart(wsClient *sdk.SocketSDK, myNodeID, router string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var decrypt dto.CliMPCEncryptData
	if err := utils.JsonUnmarshal(body, &decrypt); err != nil {
		return err
	}
	prk, err := getTempDecapsKey("keygen", myNodeID, decrypt.TaskID)
	if err != nil {
		return err
	}
	if prk == nil {
		return errors.New("temp decaps key is nil")
	}
	msg, err := ecc.DecryptMLKEM1024(prk, utils.Base64Decode(decrypt.Data), utils.Str2Bytes(utils.AddStr(decrypt.TaskID, "|", myNodeID, "|mpcKeygenStart")), nil)
	if err != nil {
		return err
	}
	var start dto.CliMPCKeygenStartRes
	if err := utils.JsonUnmarshal(msg, &start); err != nil {
		return err
	}
	if start.ExpiredTime > 0 && start.ExpiredTime < utils.UnixSecond() {
		return errors.New("mpc keygen task expired")
	}

	if err := refreshKeygenTempPrivateKeyTTL(myNodeID, start.TaskID); err != nil {
		return errors.New("handleMpcKeygenStart refresh tempPrivateKey: " + err.Error())
	}

	for _, v := range start.PublicKeyPair {
		if v.Subject == myNodeID {
			continue
		}
		if err := putTempPublicKeyFromB64("keygen", v.Subject, start.TaskID, v.PublicKey, keygenTempKeyCacheTTLSeconds); err != nil {
			return errors.New("handleMpcKeygenStart put tempPublicKey error: " + err.Error())
		}
	}

	logKeygenf("node=%s task=%s start, alg=%s threshold=%d, nodes=%v\n",
		myNodeID, start.TaskID, start.Algorithm, start.Threshold, start.NodeIDs)

	sortedIDs := mpc.SortedNodeIDs(start.NodeIDs)
	myIndex := mpc.IndexOf(sortedIDs, myNodeID)
	if myIndex < 0 {
		return errors.New("mpc keygen task myIndex invalid")
	}

	if !beginKeygenTask(start.TaskID, myNodeID) {
		logKeygenf("node=%s task=%s duplicate mpcKeygenStart rejected\n", myNodeID, start.TaskID)
		return errors.New("keygen already in progress for task")
	}

	recvCh := make(chan recvItem, mpcTssRecvChBuf)
	errCh := make(chan error, 4)
	routerStub := &wsKeygenRouter{
		taskID:   start.TaskID,
		subject:  myNodeID,
		myIndex:  myIndex,
		wsClient: wsClient,
	}

	session := &keygenSession{
		router:     routerStub,
		recvCh:     recvCh,
		errCh:      errCh,
		partyReady: make(chan struct{}, 1),
	}
	if mpc.Algorithm(start.Algorithm) == mpc.AlgEd25519 {
		session.frost = newWSFrostRouter(start.TaskID, myNodeID, "keygen", sortedIDs, myIndex, wsClient)
	} else {
		session.alice = newWSAliceRouter(start.TaskID, myNodeID, "keygen", sortedIDs, myIndex, wsClient)
	}
	registerKeygenSession(start.TaskID, myNodeID, session)
	var deliveryReady sync.WaitGroup
	deliveryReady.Add(1)
	go func() {
		deliveryReady.Done()
		runKeygenDelivery(session)
	}()
	deliveryReady.Wait()

	session.partyStarted.Store(true)
	session.notifyPartyReady()

	go func() {
		defer func() {
			endKeygenTask(start.TaskID, myNodeID)
			if unregisterKeygenSession(start.TaskID, myNodeID, session) {
				_ = keyCache.Del(utils.FNV1a64(utils.AddStr(myNodeID, ":", start.TaskID, ":keygen:tempPrivateKey")))
				for _, v := range start.NodeIDs {
					_ = keyCache.Del(tempPublicKeyCacheKey("keygen", v, start.TaskID))
				}
			}
		}()

		keyID, err := RunKeygenNodeRealByAlg(start, myNodeID, wsClient, session)
		if err != nil {
			logKeygenf("node=%s task=%s failed: %v\n", myNodeID, start.TaskID, err)
			_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, err.Error())
			return
		}

		logKeygenf("node=%s task=%s succeeded, keyID=%s, submitting result\n",
			myNodeID, start.TaskID, keyID)

		store := alg_ecdsa.NewFileKeyStore(shardKeysDir)
		if mpc.Algorithm(start.Algorithm) == mpc.AlgEd25519 {
			fstore := alg_ed25519.NewFileKeyStore(shardKeysDir)
			shareData, loadErr := fstore.Load(keyID, myNodeID)
			if loadErr != nil {
				logKeygenf("node=%s task=%s load share for result failed: %v\n", myNodeID, start.TaskID, loadErr)
				_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, "load share for result failed: "+loadErr.Error())
				return
			}
			rootPub := rootPubHexFromFrostShareData(shareData)
			if err := submitKeygenResult(wsClient, start.TaskID, myNodeID, keyID, rootPub); err != nil {
				logKeygenf("node=%s task=%s submit result failed: %v\n", myNodeID, start.TaskID, err)
				_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, "submit result failed: "+err.Error())
			}
			return
		}
		shareData, loadErr := store.Load(keyID, myNodeID)
		if loadErr != nil {
			logKeygenf("node=%s task=%s load share for result failed: %v\n", myNodeID, start.TaskID, loadErr)
			_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, "load share for result failed: "+loadErr.Error())
			return
		}
		if err := submitKeygenResult(wsClient, start.TaskID, myNodeID, keyID, rootPubHexFromShareData(shareData)); err != nil {
			logKeygenf("node=%s task=%s submit result failed: %v\n", myNodeID, start.TaskID, err)
			_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, "submit result failed: "+err.Error())
		}
	}()

	return nil
}

type wsKeygenRouter struct {
	taskID   string
	myIndex  int
	subject  string
	wsClient *sdk.SocketSDK
}
