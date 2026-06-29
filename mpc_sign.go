// 本文件：节点侧 MPC Sign 处理（HandleMpcSignStart、DeliverMpcSignMsg、早期消息缓存与 TSS 签名协议）。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/dto"
	lru "github.com/hashicorp/golang-lru/v2"
)

// ============ 早期消息缓存（mpcSignMsg 先于 session 注册到达） ============

var (
	earlySignMessages   = make(map[string]earlySignBucket) // key = taskID|myNodeID
	earlySignMessagesMu sync.Mutex
	maxEarlySignMsgs    = mpcTssRecvChBuf
	earlySignMsgTTL     = 10 * time.Minute

	// 协议消息去重：LRU + wire 内容 SHA256，避免 key 无限膨胀与手动 TTL 扫全表。
	signMsgDedupMu   sync.Mutex
	signMsgDedupOnce sync.Once
	signMsgDedup     *lru.Cache[string, struct{}]
)

const signMsgDedupLRUSize = 10000

type earlySignBucket struct {
	items     []recvItem
	createdAt time.Time
}

func signMsgDedupInit() {
	signMsgDedupOnce.Do(func() {
		c, err := lru.New[string, struct{}](signMsgDedupLRUSize)
		if err != nil {
			panic("mpc_sign: sign dedup LRU init failed: " + err.Error())
		}
		signMsgDedup = c
	})
}

func cleanupExpiredEarlySignMessagesLocked(now time.Time) {
	for k, b := range earlySignMessages {
		if now.Sub(b.createdAt) > earlySignMsgTTL {
			delete(earlySignMessages, k)
		}
	}
}

func signMsgDedupKey(taskID, myNodeID string, fromIndex int, isBroadcast bool, wireB64 string) string {
	sum := sha256.Sum256([]byte(wireB64))
	return fmt.Sprintf("%s|%s|%d|%t|%x", taskID, myNodeID, fromIndex, isBroadcast, sum)
}

func isSignMsgDuplicate(taskID, myNodeID string, fromIndex int, isBroadcast bool, wireB64 string) bool {
	signMsgDedupInit()
	signMsgDedupMu.Lock()
	defer signMsgDedupMu.Unlock()
	_, ok := signMsgDedup.Get(signMsgDedupKey(taskID, myNodeID, fromIndex, isBroadcast, wireB64))
	return ok
}

func markSignMsgProcessed(taskID, myNodeID string, fromIndex int, isBroadcast bool, wireB64 string) {
	signMsgDedupInit()
	signMsgDedupMu.Lock()
	defer signMsgDedupMu.Unlock()
	signMsgDedup.Add(signMsgDedupKey(taskID, myNodeID, fromIndex, isBroadcast, wireB64), struct{}{})
}

// RunSignNodeRealByAlg 按算法执行本节点的 CGGMP 签名逻辑。
func RunSignNodeRealByAlg(
	start dto.CliMPCSignStartRes,
	myNodeID string,
	wsClient *sdk.SocketSDK,
	session *signSession,
) (signatureHex string, needRefreshWarm bool, materialUseCount int, err error) {
	if start.RefreshWarmOnly {
		return "", false, 0, errors.New("RefreshWarmOnly task must use warm handler, not sign")
	}
	switch mpc.Algorithm(start.Algorithm) {
	case mpc.AlgECDSA:
		return runSignNodeECDSA(start, myNodeID, wsClient, session)
	case mpc.AlgEd25519:
		return runSignNodeFROST(start, myNodeID, wsClient, session)
	default:
		return "", false, 0, fmt.Errorf("unsupported MPC algorithm for sign on node: %s", mpc.Algorithm(start.Algorithm))
	}
}

func submitSignResultWithRetry(
	wsClient *sdk.SocketSDK,
	myNodeID string,
	req *dto.CliMPCSignResultReq,
	maxAttempts int,
) error {
	if wsClient == nil || req == nil {
		return errors.New("submitSignResultWithRetry invalid argument")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	backoff := []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		logSignErrf("TRACE_NODE_SUBMIT_SIGN_RESULT_BEGIN node=%s task=%s attempt=%d/%d hasErr=%t sigLen=%d",
			myNodeID, req.TaskID, i, maxAttempts, req.Err != "", len(req.SignatureHex))
		var res dto.CliMPCSignResultRes
		err := wsClient.SendWebSocketMessage("/ws/mpcSignResult", req, &res, true, true, 30)
		if err == nil && res.OK {
			logSignErrf("TRACE_NODE_SUBMIT_SIGN_RESULT_OK node=%s task=%s attempt=%d/%d hasErr=%t sigLen=%d",
				myNodeID, req.TaskID, i, maxAttempts, req.Err != "", len(req.SignatureHex))
			return nil
		}
		if err != nil {
			lastErr = err
		} else if !res.OK {
			lastErr = errors.New("server returned OK=false for mpcSignResult")
		}
		logSignErrf("TRACE_NODE_SUBMIT_SIGN_RESULT_FAILED node=%s task=%s attempt=%d/%d hasErr=%t sigLen=%d err=%v",
			myNodeID, req.TaskID, i, maxAttempts, req.Err != "", len(req.SignatureHex), lastErr)
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

func sendSignProtocolMsgWithRetry(wsClient *sdk.SocketSDK, req *dto.CliMPCEncryptData, maxAttempts int) error {
	return sendMpcProtocolMsgWithRetry(wsClient, "/ws/mpcSignMsg", req, maxAttempts)
}

// HandleMpcSignStart 处理服务端下发的 mpcSignStart Push。
func HandleMpcSignStart(wsClient *sdk.SocketSDK, myNodeID, router string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var decrypt dto.CliMPCEncryptData
	if err := utils.JsonUnmarshal(body, &decrypt); err != nil {
		return err
	}
	prk, err := getTempDecapsKey("sign", myNodeID, decrypt.TaskID)
	if err != nil {
		return err
	}
	if prk == nil {
		return errors.New("temp decaps key is nil")
	}
	msg, err := ecc.DecryptMLKEM1024(prk, utils.Base64Decode(decrypt.Data), utils.Str2Bytes(utils.AddStr(decrypt.TaskID, "|", myNodeID, "|mpcSignStart")), nil)
	if err != nil {
		return err
	}
	var start dto.CliMPCSignStartRes
	if err := utils.JsonUnmarshal(msg, &start); err != nil {
		return err
	}
	if start.ExpiredTime > 0 && start.ExpiredTime < utils.UnixSecond() {
		return errors.New("mpc sign task expired")
	}

	if err := refreshSignTempPrivateKeyTTL(myNodeID, start.TaskID); err != nil {
		return errors.New("handleMpcSignStart refresh tempPrivateKey: " + err.Error())
	}

	for _, v := range start.PublicKeyPair {
		if v.Subject == myNodeID {
			continue
		}
		if strings.TrimSpace(v.PublicKey) == "" {
			logSignErrf("TRACE_NODE_SIGN_START_SKIP_EMPTY_PUBKEY node=%s task=%s peer=%s",
				myNodeID, start.TaskID, v.Subject)
			continue
		}
		if err := putTempPublicKeyFromB64("sign", v.Subject, start.TaskID, v.PublicKey, signTempKeyCacheTTLSeconds); err != nil {
			return errors.New("handleMpcSignStart put tempPublicKey error: " + err.Error())
		}
	}

	logSignErrf("TRACE_NODE_SIGN_START_RECEIVED node=%s task=%s alg=%s keyID=%s threshold=%d warmOnly=%t allNodes=%v signNodes=%v",
		myNodeID, start.TaskID, start.Algorithm, start.KeyID, start.Threshold, start.RefreshWarmOnly, start.AllNodeIDs, start.SignNodeIDs)

	if start.RefreshWarmOnly && mpc.Algorithm(start.Algorithm) == mpc.AlgEd25519 {
		return errors.New("RefreshWarmOnly not supported for ed25519")
	}

	signParticipants := mpc.SortedNodeIDs(start.SignNodeIDs)
	if len(signParticipants) == 0 {
		signParticipants = mpc.SortedNodeIDs(start.AllNodeIDs)
	}
	myIndex := mpc.IndexOf(signParticipants, myNodeID)
	if myIndex < 0 {
		return errors.New("mpc sign task myIndex invalid")
	}

	if !beginSignTask(start.TaskID, myNodeID) {
		logSignErrf("TRACE_NODE_SIGN_START_DUPLICATE node=%s task=%s", myNodeID, start.TaskID)
		return errors.New("sign already in progress for task")
	}

	recvCh := make(chan recvItem, mpcTssRecvChBuf)
	errCh := make(chan error, 4)
	routerStub := &wsSignRouter{
		taskID:   start.TaskID,
		subject:  myNodeID,
		myIndex:  myIndex,
		wsClient: wsClient,
	}
	session := &signSession{
		router:     routerStub,
		recvCh:     recvCh,
		errCh:      errCh,
		partyReady: make(chan struct{}, 1),
	}
	if mpc.Algorithm(start.Algorithm) == mpc.AlgEd25519 {
		session.frost = newWSFrostRouter(start.TaskID, myNodeID, "sign", signParticipants, myIndex, wsClient)
	} else {
		session.alice = newWSAliceRouter(start.TaskID, myNodeID, "sign", signParticipants, myIndex, wsClient)
	}
	registerSignSession(start.TaskID, myNodeID, session)
	var deliveryReady sync.WaitGroup
	deliveryReady.Add(1)
	go func() {
		deliveryReady.Done()
		runSignDelivery(session)
	}()
	deliveryReady.Wait()

	session.partyStarted.Store(true)
	session.notifyPartyReady()

	go func() {
		defer func() {
			endSignTask(start.TaskID, myNodeID)
			if unregisterSignSession(start.TaskID, myNodeID, session) {
				clearSignTempKeys(myNodeID, start.TaskID, start.AllNodeIDs)
			}
		}()

		nodeID := myNodeID
		if start.RefreshWarmOnly {
			warmErr := runWarmRefreshNodeECDSA(start, myNodeID, wsClient, session)
			req := &dto.CliMPCSignResultReq{
				TaskID:        start.TaskID,
				NodeID:        nodeID,
				KeyID:         start.KeyID,
				RefreshWarmOK: warmErr == nil,
			}
			if warmErr != nil {
				req.Err = warmErr.Error()
				logSignErrf("TRACE_NODE_REFRESH_WARM_FAILED node=%s task=%s err=%v", myNodeID, start.TaskID, warmErr)
			} else {
				logSignErrf("TRACE_NODE_REFRESH_WARM_OK node=%s task=%s keyID=%s", myNodeID, start.TaskID, start.KeyID)
			}
			if submitErr := submitSignResultWithRetry(wsClient, myNodeID, req, 3); submitErr != nil {
				logSignErrf("TRACE_NODE_SUBMIT_WARM_RESULT_FAILED node=%s task=%s err=%v", myNodeID, start.TaskID, submitErr)
			}
			return
		}

		sigHex, needRefreshWarm, materialUseCount, err := RunSignNodeRealByAlg(start, myNodeID, wsClient, session)
		if err != nil {
			logSignErrf("TRACE_NODE_SIGN_FAILED node=%s task=%s err=%v", myNodeID, start.TaskID, err)
			req := &dto.CliMPCSignResultReq{
				TaskID: start.TaskID,
				NodeID: nodeID,
				KeyID:  start.KeyID,
				Err:    err.Error(),
			}
			if submitErr := submitSignResultWithRetry(wsClient, myNodeID, req, 3); submitErr != nil {
				logSignErrf("TRACE_NODE_SUBMIT_ERROR_RESULT_FINAL_FAILED node=%s task=%s err=%v", myNodeID, start.TaskID, submitErr)
			}
			return
		}

		logSignErrf("TRACE_NODE_SIGN_SUCCEEDED node=%s task=%s keyID=%s sigLen=%d needRefreshWarm=%t useCount=%d",
			myNodeID, start.TaskID, start.KeyID, len(sigHex), needRefreshWarm, materialUseCount)
		req := &dto.CliMPCSignResultReq{
			TaskID:           start.TaskID,
			NodeID:           nodeID,
			KeyID:            start.KeyID,
			SignatureHex:     sigHex,
			NeedRefreshWarm:  needRefreshWarm,
			MaterialUseCount: materialUseCount,
		}
		if err := submitSignResultWithRetry(wsClient, myNodeID, req, 3); err != nil {
			logSignErrf("TRACE_NODE_SUBMIT_SIGN_RESULT_FINAL_FAILED node=%s task=%s err=%v", myNodeID, start.TaskID, err)
		}
	}()

	return nil
}

type wsSignRouter struct {
	taskID   string
	myIndex  int
	subject  string
	wsClient *sdk.SocketSDK
}

type signSession struct {
	router       *wsSignRouter
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

func (s *signSession) notifyPartyReady() {
	select {
	case s.partyReady <- struct{}{}:
	default:
	}
}

func (s *signSession) enqueue(item recvItem) bool {
	return enqueueRecvItem(s.recvCh, &s.closed, &s.mu, func() {
		logSignErrf("TRACE_NODE_SIGN_RECVCH_WAIT node=%s task=%s fromIndex=%d (recvCh full, still waiting)",
			s.router.subject, s.router.taskID, item.FromIndex)
	}, item)
}

func (s *signSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.recvCh)
	s.mu.Unlock()
}

var (
	signSessions   = make(map[string]*signSession)
	signSessionsMu sync.RWMutex
	signActiveMu   sync.Mutex
	signActive     = make(map[string]struct{}) // taskID|nodeID，防止重复 mpcSignStart 起两个 RunSign
)

func beginSignTask(taskID, nodeID string) bool {
	key := signSessionKey(taskID, nodeID)
	signActiveMu.Lock()
	defer signActiveMu.Unlock()
	if _, ok := signActive[key]; ok {
		return false
	}
	signActive[key] = struct{}{}
	return true
}

func endSignTask(taskID, nodeID string) {
	key := signSessionKey(taskID, nodeID)
	signActiveMu.Lock()
	delete(signActive, key)
	signActiveMu.Unlock()
}

func signSessionKey(taskID, nodeID string) string {
	return taskID + "|" + nodeID
}

func registerSignSession(taskID, nodeID string, s *signSession) {
	key := signSessionKey(taskID, nodeID)

	var replayItems []recvItem
	earlySignMessagesMu.Lock()
	cleanupExpiredEarlySignMessagesLocked(time.Now())
	if b, ok := earlySignMessages[key]; ok {
		replayItems = b.items
		delete(earlySignMessages, key)
	}
	earlySignMessagesMu.Unlock()

	signSessionsMu.Lock()
	old := signSessions[key]
	if old != nil && old != s {
		old.close()
		logSignf("registerSignSession: replaced stale session task=%s node=%s old=%p new=%p\n",
			taskID, nodeID, old, s)
	}
	signSessions[key] = s
	logSignf("registerSignSession: task=%s node=%s replay=%d\n", taskID, nodeID, len(replayItems))
	signSessionsMu.Unlock()

	for _, item := range replayItems {
		if !s.enqueue(item) {
			logSignf("replay early msg failed task=%s node=%s\n", taskID, nodeID)
		}
	}
}

func unregisterSignSession(taskID, nodeID string, s *signSession) bool {
	key := signSessionKey(taskID, nodeID)

	signSessionsMu.Lock()
	cur := signSessions[key]
	if cur != s {
		signSessionsMu.Unlock()
		logSignf("unregisterSignSession: stale skip task=%s node=%s want=%p cur=%p\n",
			taskID, nodeID, s, cur)
		return false
	}
	delete(signSessions, key)
	signSessionsMu.Unlock()

	earlySignMessagesMu.Lock()
	delete(earlySignMessages, key)
	earlySignMessagesMu.Unlock()

	logSignf("unregisterSignSession: task=%s node=%s deleted=%p\n", taskID, nodeID, s)
	return true
}

// finishSignOutbound 关闭 outCh、停止 delivery、阻塞至异步 Send 全部完成。
// 若 drain 阶段 Send 失败（主循环已因 endCh 返回时），返回该错误供 RunSign 上报失败而非误报成功。
func (s *signSession) finishSignOutbound(closeOutCh func()) error {
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

func getSignSession(taskID, nodeID string) *signSession {
	signSessionsMu.RLock()
	defer signSessionsMu.RUnlock()
	return signSessions[signSessionKey(taskID, nodeID)]
}

func runSignDelivery(s *signSession) {
	logSignf("task=%s myIndex=%d delivery started\n", s.router.taskID, s.router.myIndex)
	var earlyMsgs []recvItem

	flushEarly := func(trigger *recvItem) {
		if !s.partyStarted.Load() {
			if trigger != nil {
				if len(earlyMsgs) < maxEarlySignMsgs {
					earlyMsgs = append(earlyMsgs, *trigger)
					logSignf("task=%s cached early msg fromIndex=%d (total=%d)\n",
						s.router.taskID, trigger.FromIndex, len(earlyMsgs))
				} else {
					logSignf("task=%s dropped early msg (buffer full) fromIndex=%d\n",
						s.router.taskID, trigger.FromIndex)
				}
			}
			return
		}
		if n := len(earlyMsgs); n > 0 {
			logSignErrf("TRACE_NODE_SIGN_FLUSH_EARLY node=%s task=%s count=%d",
				s.router.subject, s.router.taskID, n)
			for _, early := range earlyMsgs {
				processSignMessage(s, early)
			}
			earlyMsgs = nil
		}
		if trigger != nil {
			processSignMessage(s, *trigger)
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

func processSignMessage(s *signSession, item recvItem) {
	wireB64 := base64.StdEncoding.EncodeToString(item.WireBytes)
	if isSignMsgDuplicate(s.router.taskID, s.router.subject, item.FromIndex, item.IsBroadcast, wireB64) {
		logSignErrf("TRACE_NODE_SIGN_DEDUP_SKIP node=%s task=%s fromIndex=%d broadcast=%v",
			s.router.subject, s.router.taskID, item.FromIndex, item.IsBroadcast)
		return
	}
	var err error
	if s.frost != nil {
		err = s.frost.Receive(item.FromIndex, item.WireBytes)
	} else if s.alice != nil {
		err = s.alice.Receive(item.FromIndex, item.WireBytes)
	} else {
		err = fmt.Errorf("sign session missing wire router")
	}
	if err != nil && err.Error() != "Error is nil" {
		logSignErrf("TRACE_NODE_SIGN_UPDATE_FAILED node=%s task=%s fromIndex=%d err=%v (not deduped, retry allowed)",
			s.router.subject, s.router.taskID, item.FromIndex, err)
		deliverSessionErr(s.errCh, err)
		return
	}
	markSignMsgProcessed(s.router.taskID, s.router.subject, item.FromIndex, item.IsBroadcast, wireB64)
	atomic.AddUint32(&s.recvCount, 1)
}

// DeliverMpcSignMsg 由 Push 回调调用。
func DeliverMpcSignMsg(wsClient *sdk.SocketSDK, myNodeID, router string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var decrypt dto.CliMPCEncryptData
	if err := utils.JsonUnmarshal(body, &decrypt); err != nil {
		return err
	}
	prk, err := getTempDecapsKey("sign", myNodeID, decrypt.TaskID)
	if err != nil {
		return err
	}
	if prk == nil {
		logSignErrf("TRACE_NODE_SIGN_DELIVER_NO_DECAPS_KEY node=%s task=%s (temp key expired or missing?)",
			myNodeID, decrypt.TaskID)
		return errors.New("temp decaps key is nil")
	}
	msg, err := ecc.DecryptMLKEM1024(prk, utils.Base64Decode(decrypt.Data), utils.Str2Bytes(utils.AddStr(decrypt.TaskID, "|", myNodeID, "|mpcSignMsg")), nil)
	if err != nil {
		logSignErrf("TRACE_NODE_SIGN_DELIVER_DECRYPT_FAILED node=%s task=%s err=%v", myNodeID, decrypt.TaskID, err)
		return err
	}
	var res dto.CliMPCSignMsgRes
	if err := utils.JsonUnmarshal(msg, &res); err != nil {
		return err
	}

	s := getSignSession(res.TaskID, myNodeID)
	if s == nil || s.router == nil {
		wireBytes, err := base64.StdEncoding.DecodeString(res.WireBytesBase64)
		if err != nil {
			return err
		}
		sessionKey := signSessionKey(res.TaskID, myNodeID)
		earlySignMessagesMu.Lock()
		now := time.Now()
		cleanupExpiredEarlySignMessagesLocked(now)
		if b, exists := earlySignMessages[sessionKey]; exists && len(b.items) >= maxEarlySignMsgs {
			earlySignMessagesMu.Unlock()
			return nil
		}
		item := recvItem{WireBytes: wireBytes, FromIndex: res.FromIndex, IsBroadcast: res.IsBroadcast}
		b := earlySignMessages[sessionKey]
		if b.createdAt.IsZero() {
			b.createdAt = now
		}
		dup := false
		for _, existing := range b.items {
			if existing.FromIndex == item.FromIndex &&
				existing.IsBroadcast == item.IsBroadcast &&
				bytes.Equal(existing.WireBytes, item.WireBytes) {
				dup = true
				break
			}
		}
		if !dup {
			b.items = append(b.items, item)
		}
		earlySignMessages[sessionKey] = b
		earlySignMessagesMu.Unlock()
		return nil
	}

	if res.FromIndex == s.router.myIndex {
		return nil
	}
	wireBytes, err := base64.StdEncoding.DecodeString(res.WireBytesBase64)
	if err != nil {
		return err
	}
	item := recvItem{WireBytes: wireBytes, FromIndex: res.FromIndex, IsBroadcast: res.IsBroadcast}
	if !s.enqueue(item) {
		logSignErrf("TRACE_NODE_SIGN_DELIVER_ENQUEUE_SKIP node=%s task=%s fromIndex=%d (session closed?)",
			myNodeID, res.TaskID, res.FromIndex)
		return nil
	}
	return nil
}
