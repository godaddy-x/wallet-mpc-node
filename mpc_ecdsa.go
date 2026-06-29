// ????Alice CGGMP ECDSA ?? WS ?????? keygen/sign ???
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ecdsa"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

const (
	ecdsaKeygenTimeout = 11 * time.Minute
	ecdsaSignTimeout   = 12 * time.Minute
)

var (
	ecdsaWarmCancelMu  sync.Mutex
	ecdsaWarmCancels   = make(map[string]uint64) // sessionKey -> cancel generation id
	ecdsaWarmCancelFn  = make(map[uint64]context.CancelFunc)
	ecdsaWarmCancelGen atomic.Uint64
)

func cancelPriorEcdsaWarm(sessionKey string) {
	ecdsaWarmCancelMu.Lock()
	if id, ok := ecdsaWarmCancels[sessionKey]; ok {
		if fn, ok := ecdsaWarmCancelFn[id]; ok {
			fn()
			delete(ecdsaWarmCancelFn, id)
		}
		delete(ecdsaWarmCancels, sessionKey)
	}
	ecdsaWarmCancelMu.Unlock()
}

func registerEcdsaWarmCancel(sessionKey string, cancel context.CancelFunc) uint64 {
	id := ecdsaWarmCancelGen.Add(1)
	ecdsaWarmCancelMu.Lock()
	ecdsaWarmCancels[sessionKey] = id
	ecdsaWarmCancelFn[id] = cancel
	ecdsaWarmCancelMu.Unlock()
	return id
}

func unregisterEcdsaWarmCancel(sessionKey string, id uint64) {
	ecdsaWarmCancelMu.Lock()
	if cur, ok := ecdsaWarmCancels[sessionKey]; ok && cur == id {
		delete(ecdsaWarmCancels, sessionKey)
	}
	delete(ecdsaWarmCancelFn, id)
	ecdsaWarmCancelMu.Unlock()
}

func ecdsaWarmSessionKey(keyID string, participants []string) string {
	return keyID + "|" + strings.Join(mpc.SortedNodeIDs(participants), ",")
}

func ecdsaKeySessionLock(keyID string, participants []string) *sync.Mutex {
	return mpcKeySessionLock(keyID, participants)
}

type wsAliceRouter struct {
	taskID    string
	subject   string
	sortedIDs []string
	myIndex   int
	wsClient  *sdk.SocketSDK
	module    string // "keygen" | "sign"

	inbox   *alg_ecdsa.Inbox
	partPub *alg_ecdsa.PartialPubCollector
	phaseMu sync.RWMutex
	phase   string
}

func newWSAliceRouter(taskID, subject, module string, sortedIDs []string, myIndex int, ws *sdk.SocketSDK) *wsAliceRouter {
	return &wsAliceRouter{
		taskID:    taskID,
		subject:   subject,
		sortedIDs: sortedIDs,
		myIndex:   myIndex,
		wsClient:  ws,
		module:    module,
		inbox:     alg_ecdsa.NewInbox(),
	}
}

func (r *wsAliceRouter) setPhase(phase string) {
	r.phaseMu.Lock()
	r.phase = phase
	r.phaseMu.Unlock()
}

func (r *wsAliceRouter) nodeIDAt(index int) string {
	if index < 0 || index >= len(r.sortedIDs) {
		return ""
	}
	return r.sortedIDs[index]
}

func (r *wsAliceRouter) sendWire(targetNodeID, wireB64 string) error {
	return sendMPCProtocolWire(r.wsClient, r.taskID, r.module, r.myIndex, targetNodeID, wireB64)
}

func (r *wsAliceRouter) peerManager() *alg_ecdsa.WSPeerManager {
	return alg_ecdsa.NewWSPeerManager(r.subject, r.sortedIDs, r.sendWire)
}

func (r *wsAliceRouter) Receive(fromIndex int, wireBytes []byte) error {
	if fromIndex < 0 || fromIndex >= len(r.sortedIDs) || fromIndex == r.myIndex {
		return nil
	}
	fromNodeID := r.nodeIDAt(fromIndex)
	wireB64 := base64.StdEncoding.EncodeToString(wireBytes)
	// ??? DKG ???????? partial pub???????? DKG???????
	if len(wireBytes) >= 1 && wireBytes[0] == alg_ecdsa.WireModulePartPub && r.partPub != nil {
		return r.partPub.Deliver(fromNodeID, wireB64)
	}
	return r.inbox.Deliver(fromNodeID, wireB64)
}

func runKeygenNodeECDSA(start dto.CliMPCKeygenStartRes, myNodeID string, wsClient *sdk.SocketSDK, session *keygenSession) (keyID string, err error) {
	if session == nil || session.alice == nil {
		return "", errors.New("keygen session is nil")
	}
	alice := session.alice
	sortedIDs := alice.sortedIDs
	threshold := uint32(start.Threshold)

	ctx, cancel := context.WithTimeout(context.Background(), ecdsaKeygenTimeout)
	defer cancel()

	alice.partPub = alg_ecdsa.NewPartialPubCollector(myNodeID, sortedIDs)
	alice.setPhase("dkg")
	pm := alice.peerManager()
	logKeygenf("node=%s task=%s phase=dkg begin\n", myNodeID, start.TaskID)
	dkgResult, err := alg_ecdsa.RunDKG(ctx, start.TaskID, myNodeID, sortedIDs, threshold, pm, alice.inbox)
	if err != nil {
		return "", err
	}
	keyID = alg_ecdsa.KeyIDFromPubXY(dkgResult.PublicKey.GetX(), dkgResult.PublicKey.GetY())
	logKeygenf("node=%s task=%s phase=dkg done keyID=%s waiting partial pub (%d peers)\n",
		myNodeID, start.TaskID, keyID, len(sortedIDs)-1)

	alice.setPhase("partpub")
	partialJSON, err := alg_ecdsa.RunPartialPubExchange(ctx, myNodeID, sortedIDs, dkgResult.Share, pm, alice.partPub)
	if err != nil {
		return "", err
	}
	logKeygenf("node=%s task=%s phase=partpub done\n", myNodeID, start.TaskID)
	alice.setPhase("idle")

	shareData := alg_ecdsa.BuildNodeShareData(keyID, myNodeID, start.TaskID, sortedIDs, threshold, dkgResult, partialJSON)
	store := alg_ecdsa.NewFileKeyStore(shardKeysDir)
	if err := store.Save(shareData); err != nil {
		return "", fmt.Errorf("save ecdsa share: %w", err)
	}
	return keyID, nil
}

func runWarmRefreshNodeECDSA(start dto.CliMPCSignStartRes, myNodeID string, wsClient *sdk.SocketSDK, session *signSession) error {
	if session == nil || session.alice == nil {
		return errors.New("warm session is nil")
	}
	alice := session.alice
	participants := alice.sortedIDs
	sessionKey := ecdsaWarmSessionKey(start.KeyID, participants)
	cancelPriorEcdsaWarm(sessionKey)

	ctx, cancel := context.WithTimeout(context.Background(), ecdsaSignTimeout)
	warmID := registerEcdsaWarmCancel(sessionKey, cancel)
	defer func() {
		unregisterEcdsaWarmCancel(sessionKey, warmID)
		cancel()
	}()

	lock := ecdsaKeySessionLock(start.KeyID, participants)
	lock.Lock()
	defer lock.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	store := alg_ecdsa.NewFileKeyStore(shardKeysDir)
	shareData, err := store.Load(start.KeyID, myNodeID)
	if err != nil {
		return fmt.Errorf("load ecdsa share for warm: %w", err)
	}
	pm := alice.peerManager()
	alice.setPhase("refresh")
	logSignErrf("TRACE_NODE_REFRESH_WARM node=%s task=%s keyID=%s", myNodeID, start.TaskID, start.KeyID)
	if err := alg_ecdsa.RunWarmRefresh(ctx, myNodeID, participants, uint32(start.Threshold), shareData, pm, alice.inbox); err != nil {
		if errors.Is(err, context.Canceled) {
			logSignErrf("TRACE_NODE_REFRESH_WARM_CANCELED node=%s task=%s", myNodeID, start.TaskID)
		}
		alg_ecdsa.DefaultSignMaterialPool.MarkWarmFailed(
			alg_ecdsa.MaterialSessionKey(start.KeyID, myNodeID, participants))
		alice.setPhase("idle")
		return err
	}
	alice.setPhase("idle")
	return nil
}

func runSignNodeECDSA(start dto.CliMPCSignStartRes, myNodeID string, wsClient *sdk.SocketSDK, session *signSession) (signatureHex string, needRefreshWarm bool, materialUseCount int, err error) {
	if session == nil || session.alice == nil {
		return "", false, 0, errors.New("sign session is nil")
	}
	if start.SignData.AccountIndex < 0 || start.SignData.Change < 0 || start.SignData.AddressIndex < 0 {
		return "", false, 0, fmt.Errorf("mpc: invalid sign path")
	}
	alice := session.alice
	participants := alice.sortedIDs
	if len(participants) < start.Threshold {
		return "", false, 0, fmt.Errorf("mpc: insufficient sign participants %d < threshold %d", len(participants), start.Threshold)
	}

	lock := ecdsaKeySessionLock(start.KeyID, participants)
	lock.Lock()
	defer lock.Unlock()

	store := alg_ecdsa.NewFileKeyStore(shardKeysDir)
	shareData, err := store.Load(start.KeyID, myNodeID)
	if err != nil {
		return "", false, 0, fmt.Errorf("load ecdsa share: %w", err)
	}
	msgHash, err := hd.MessageHashFromTxHash(start.SignData.Message)
	if err != nil {
		return "", false, 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), ecdsaSignTimeout)
	defer cancel()

	enableAliceProtocolTrace()
	mpc.ClearAliceProtocolLog()

	pm := alice.peerManager()
	alice.setPhase("sign")
	logSignErrf("TRACE_NODE_SIGN_PHASE node=%s task=%s phase=sign-only begin", myNodeID, start.TaskID)
	out, err := alg_ecdsa.RunSignSession(
		ctx,
		start.TaskID,
		myNodeID,
		participants,
		uint32(start.Threshold),
		shareData,
		msgHash,
		uint32(start.SignData.AccountIndex),
		uint32(start.SignData.Change),
		uint32(start.SignData.AddressIndex),
		pm,
		alice.inbox,
	)
	if err != nil {
		return "", false, 0, err
	}
	alice.setPhase("idle")
	return out.SignatureHex, out.NeedRefreshWarm, out.MaterialUseCount, nil
}

func submitKeygenResult(wsClient *sdk.SocketSDK, taskID, nodeID, keyID, rootPubHex string) error {
	req := &dto.CliMPCKeygenResultReq{
		TaskID:     taskID,
		NodeID:     nodeID,
		KeyID:      keyID,
		RootPubHex: rootPubHex,
	}
	return submitKeygenResultWithRetry(wsClient, req, 3)
}

func rootPubHexFromShareData(data *alg_ecdsa.NodeShareData) string {
	if data == nil {
		return ""
	}
	x, ok := new(big.Int).SetString(data.PubX, 10)
	if !ok {
		return ""
	}
	y, ok := new(big.Int).SetString(data.PubY, 10)
	if !ok {
		return ""
	}
	b := make([]byte, 65)
	b[0] = 0x04
	copy(b[1:33], hd.Pad32(x.Bytes()))
	copy(b[33:65], hd.Pad32(y.Bytes()))
	return hex.EncodeToString(b)
}
