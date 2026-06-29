// 本文件：Alice FROST Ed25519 协议 WS 路由与节点侧 keygen/sign 执行。
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ed25519"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

const (
	frostKeygenTimeout = 11 * time.Minute
	frostSignTimeout   = 12 * time.Minute
)

func frostKeySessionLock(keyID string, participants []string) *sync.Mutex {
	return mpcKeySessionLock(keyID, participants)
}

type wsFrostRouter struct {
	taskID    string
	subject   string
	sortedIDs []string
	myIndex   int
	wsClient  *sdk.SocketSDK
	module    string

	inbox   *alg_ed25519.Inbox
	phaseMu sync.RWMutex
	phase   string
}

func newWSFrostRouter(taskID, subject, module string, sortedIDs []string, myIndex int, ws *sdk.SocketSDK) *wsFrostRouter {
	return &wsFrostRouter{
		taskID:    taskID,
		subject:   subject,
		sortedIDs: sortedIDs,
		myIndex:   myIndex,
		wsClient:  ws,
		module:    module,
		inbox:     alg_ed25519.NewInbox(),
	}
}

func (r *wsFrostRouter) setPhase(phase string) {
	r.phaseMu.Lock()
	r.phase = phase
	r.phaseMu.Unlock()
}

func (r *wsFrostRouter) nodeIDAt(index int) string {
	if index < 0 || index >= len(r.sortedIDs) {
		return ""
	}
	return r.sortedIDs[index]
}

func (r *wsFrostRouter) sendWire(targetNodeID, wireB64 string) error {
	return sendMPCProtocolWire(r.wsClient, r.taskID, r.module, r.myIndex, targetNodeID, wireB64)
}

func (r *wsFrostRouter) peerManager() *alg_ed25519.WSPeerManager {
	return alg_ed25519.NewWSPeerManager(r.subject, r.sortedIDs, r.sendWire)
}

func (r *wsFrostRouter) Receive(fromIndex int, wireBytes []byte) error {
	if fromIndex < 0 || fromIndex >= len(r.sortedIDs) || fromIndex == r.myIndex {
		return nil
	}
	fromNodeID := r.nodeIDAt(fromIndex)
	wireB64 := base64.StdEncoding.EncodeToString(wireBytes)
	return r.inbox.Deliver(fromNodeID, wireB64)
}

func runKeygenNodeFROST(start dto.CliMPCKeygenStartRes, myNodeID string, wsClient *sdk.SocketSDK, session *keygenSession) (keyID string, err error) {
	router := session.frost
	if router == nil {
		return "", errors.New("keygen frost router is nil")
	}
	sortedIDs := router.sortedIDs
	threshold := uint32(start.Threshold)

	ctx, cancel := context.WithTimeout(context.Background(), frostKeygenTimeout)
	defer cancel()

	router.setPhase("dkg")
	pm := router.peerManager()
	logKeygenf("node=%s task=%s phase=frost-dkg begin\n", myNodeID, start.TaskID)
	dkgResult, err := alg_ed25519.RunDKG(ctx, myNodeID, sortedIDs, threshold, pm, router.inbox)
	if err != nil {
		return "", err
	}
	pubHex, err := alg_ed25519.PubHexFromPoint(dkgResult.PublicKey)
	if err != nil {
		return "", err
	}
	keyID = alg_ed25519.KeyIDFromPubHex(pubHex)
	logKeygenf("node=%s task=%s phase=frost-dkg done keyID=%s\n", myNodeID, start.TaskID, keyID)
	router.setPhase("idle")

	shareData, err := alg_ed25519.BuildNodeShareData(keyID, myNodeID, start.TaskID, sortedIDs, threshold, dkgResult)
	if err != nil {
		return "", err
	}
	store := alg_ed25519.NewFileKeyStore(shardKeysDir)
	if err := store.Save(shareData); err != nil {
		return "", fmt.Errorf("save frost share: %w", err)
	}
	return keyID, nil
}

func runSignNodeFROST(start dto.CliMPCSignStartRes, myNodeID string, wsClient *sdk.SocketSDK, session *signSession) (signatureHex string, needRefreshWarm bool, materialUseCount int, err error) {
	router := session.frost
	if router == nil {
		return "", false, 0, errors.New("sign frost router is nil")
	}
	if start.SignData.AccountIndex < 0 || start.SignData.Change < 0 || start.SignData.AddressIndex < 0 {
		return "", false, 0, fmt.Errorf("mpc: invalid sign path")
	}
	participants := router.sortedIDs
	if len(participants) < start.Threshold {
		return "", false, 0, fmt.Errorf("mpc: insufficient sign participants %d < threshold %d", len(participants), start.Threshold)
	}

	lock := frostKeySessionLock(start.KeyID, participants)
	lock.Lock()
	defer lock.Unlock()

	store := alg_ed25519.NewFileKeyStore(shardKeysDir)
	shareData, err := store.Load(start.KeyID, myNodeID)
	if err != nil {
		return "", false, 0, fmt.Errorf("load frost share: %w", err)
	}
	msg, err := alg_ed25519.MessageBytesFromHex(start.SignData.Message)
	if err != nil {
		return "", false, 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), frostSignTimeout)
	defer cancel()

	enableAliceProtocolTrace()
	mpc.ClearAliceProtocolLog()

	pm := router.peerManager()
	router.setPhase("sign")
	logSignErrf("TRACE_NODE_SIGN_PHASE node=%s task=%s phase=frost-sign begin", myNodeID, start.TaskID)
	out, err := alg_ed25519.RunSign(
		ctx,
		myNodeID,
		participants,
		uint32(start.Threshold),
		shareData,
		msg,
		uint32(start.SignData.AccountIndex),
		uint32(start.SignData.Change),
		uint32(start.SignData.AddressIndex),
		pm,
		router.inbox,
	)
	if err != nil {
		return "", false, 0, err
	}
	router.setPhase("idle")
	return out.SignatureHex, false, 0, nil
}

func rootPubHexFromFrostShareData(data *alg_ed25519.NodeShareData) string {
	h, err := alg_ed25519.RootPubHexFromShareData(data)
	if err != nil {
		return ""
	}
	return h
}
