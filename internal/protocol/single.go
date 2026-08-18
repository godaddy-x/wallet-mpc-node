package protocol

import (
	"context"
	"errors"
	"time"

	"github.com/godaddy-x/freego/client/ws"
	"github.com/godaddy-x/wallet-mpc-node/internal/config"
	"github.com/godaddy-x/wallet-mpc-node/internal/log"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_single"
	"github.com/godaddy-x/wallet-mpc-node/types"
)

func runSingleKeygenLocal(start types.CliMPCKeygenStartRes, myNodeID string, session *keygenSession) (keyID, rootPubHex string, err error) {
	var abortCtx context.Context
	if session != nil {
		abortCtx = session.abortCtx
	}
	if err := checkSessionAborted(abortCtx, start.TaskID); err != nil {
		return "", "", err
	}
	alg, err := mpc.ParseAlgorithm(start.Algorithm)
	if err != nil {
		return "", "", err
	}
	store := alg_single.NewFileKeyStore(config.ShardKeysDir())
	keyID, rootPubHex, err = alg_single.RunKeygen(alg, store, myNodeID, start.TaskID)
	if err != nil {
		return "", "", err
	}
	if session != nil {
		session.markPersistedKey(keyID)
	}
	if err := checkSessionAborted(abortCtx, start.TaskID); err != nil {
		return keyID, rootPubHex, err
	}
	return keyID, rootPubHex, nil
}

func runSingleKeygen(start types.CliMPCKeygenStartRes, myNodeID string, wsClient *ws.SDK, session *keygenSession) error {
	keyID, rootPubHex, err := runSingleKeygenLocal(start, myNodeID, session)
	if err != nil {
		log.Keygenf("node=%s task=%s single keygen failed: %v\n", myNodeID, start.TaskID, err)
		if !isTaskAborted(start.TaskID) {
			_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, err.Error())
		}
		return err
	}
	if isTaskAborted(start.TaskID) {
		return errors.New("keygen task aborted")
	}
	log.Keygenf("node=%s task=%s single keygen ok keyID=%s\n", myNodeID, start.TaskID, keyID)
	if err := submitKeygenResult(wsClient, start.TaskID, myNodeID, keyID, rootPubHex); err != nil {
		log.Keygenf("node=%s task=%s submit result failed: %v\n", myNodeID, start.TaskID, err)
		if !isTaskAborted(start.TaskID) {
			_ = submitKeygenResultErr(wsClient, start.TaskID, myNodeID, "submit result failed: "+err.Error())
		}
		return err
	}
	return nil
}

func runSingleSignLocal(start types.CliMPCSignStartRes, myNodeID string) (signatureHex, algorithm string, err error) {
	store := alg_single.NewFileKeyStore(config.ShardKeysDir())
	data, err := store.Load(start.KeyID, myNodeID)
	if err != nil {
		return "", "", err
	}
	if err := alg_single.ValidateLoadedKey(data, start.KeyID, myNodeID, start.Algorithm); err != nil {
		return "", "", err
	}
	sigHex, err := alg_single.RunSign(data, start.SignData)
	if err != nil {
		return "", "", err
	}
	return sigHex, data.Algorithm, nil
}

func submitSingleSignErr(wsClient *ws.SDK, myNodeID string, start types.CliMPCSignStartRes, errMsg string) error {
	req := &types.CliMPCSignResultReq{
		TaskID: start.TaskID,
		NodeID: myNodeID,
		KeyID:  start.KeyID,
		Err:    errMsg,
	}
	_ = submitSignResultWithRetry(wsClient, myNodeID, req, 3)
	return errors.New(errMsg)
}

func runSingleSign(start types.CliMPCSignStartRes, myNodeID string, wsClient *ws.SDK, session *signSession) error {
	taskStart := time.Now()
	if start.KeyID == "" {
		return submitSingleSignErr(wsClient, myNodeID, start, "mpc sign task keyID is empty")
	}
	var abortCtx context.Context
	if session != nil {
		abortCtx = session.abortCtx
	}
	if err := checkSessionAborted(abortCtx, start.TaskID); err != nil {
		return err
	}
	signStart := time.Now()
	sigHex, algorithm, err := runSingleSignLocal(start, myNodeID)
	signMs := time.Since(signStart).Milliseconds()
	if err != nil {
		if isTaskAborted(start.TaskID) {
			return err
		}
		return submitSingleSignErr(wsClient, myNodeID, start, err.Error())
	}
	if err := checkSessionAborted(abortCtx, start.TaskID); err != nil {
		return err
	}
	submitStart := time.Now()
	req := &types.CliMPCSignResultReq{
		TaskID:       start.TaskID,
		NodeID:       myNodeID,
		KeyID:        start.KeyID,
		SignatureHex: sigHex,
	}
	if err := submitSignResultWithRetry(wsClient, myNodeID, req, 3); err != nil {
		return err
	}
	submitMs := time.Since(submitStart).Milliseconds()
	totalMs := time.Since(taskStart).Milliseconds()
	log.SignTimingf("node=%s task=%s keyID=%s alg=%s total_ms=%d sign_ms=%d submit_ms=%d hd=%d/%d/%d",
		myNodeID, start.TaskID, start.KeyID, algorithm,
		totalMs, signMs, submitMs,
		start.SignData.AccountIndex, start.SignData.Change, start.SignData.AddressIndex)
	return nil
}
