package protocol

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godaddy-x/wallet-mpc-node/mpc/alg_ecdsa"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

func TestTryMarkTaskAbortedIdempotent(t *testing.T) {
	taskID := "abort-idem-" + time.Now().Format("150405.000")
	if !tryMarkTaskAborted(taskID) {
		t.Fatal("first mark should succeed")
	}
	if tryMarkTaskAborted(taskID) {
		t.Fatal("second mark should be rejected")
	}
	if !isTaskAborted(taskID) {
		t.Fatal("should remain aborted")
	}
}

func TestDeleteUnconfirmedKeygenShareBySessionID(t *testing.T) {
	dir := t.TempDir()
	keystore.SetEncryptionKey("test-abort-share-key")
	t.Cleanup(func() { keystore.SetEncryptionKey("") })

	store := alg_ecdsa.NewFileKeyStore(dir)
	taskID := "task-del-1"
	keyID := "key-del-1"
	nodeID := "node0"
	data := &alg_ecdsa.NodeShareData{
		KeyID:      keyID,
		NodeID:     nodeID,
		SessionID:  taskID,
		Share:      "1",
		PubX:       "2",
		PubY:       "3",
		AllNodeIDs: []string{nodeID},
		Threshold:  1,
	}
	if err := store.Save(data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, keyID+"-"+nodeID+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("share should exist: %v", err)
	}

	loaded, err := store.Load(keyID, nodeID)
	if err != nil || loaded.SessionID != taskID {
		t.Fatalf("load failed: %v %+v", err, loaded)
	}
	if err := store.Delete(keyID, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("share should be deleted, err=%v", err)
	}
}

func TestAbortTaskSessionCancelsLateRegisteredSession(t *testing.T) {
	taskID := "task-late-reg-" + time.Now().Format("150405.000000")
	nodeID := "node-late"
	if !tryMarkTaskAborted(taskID) {
		t.Fatal("pre-mark should succeed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &keygenSession{
		recvCh:      make(chan recvItem, 1),
		errCh:       make(chan error, 4),
		abortCtx:    ctx,
		abortCancel: cancel,
		router:      &wsKeygenRouter{taskID: taskID, subject: nodeID},
	}
	registerKeygenSession(taskID, nodeID, s)
	t.Cleanup(func() {
		endKeygenTask(taskID, nodeID)
		unregisterKeygenSession(taskID, nodeID, s)
	})
	if err := stopIfTaskAborted(nil, nodeID, taskID, "keygen"); err == nil {
		t.Fatal("expected aborted error after late register")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("abortCtx should be canceled after late register")
	}
	if getKeygenSession(taskID, nodeID) != nil {
		t.Fatal("session should be unregistered")
	}
}

func TestStartingTaskVisibleToDisconnectScan(t *testing.T) {
	taskID := "task-starting-" + time.Now().Format("150405.000000")
	nodeID := "node-start"
	noteStartingTask(taskID, nodeID)
	t.Cleanup(func() { clearStartingTask(taskID, nodeID) })
	found := false
	for _, id := range listStartingTaskIDs(nodeID) {
		if id == taskID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("starting task should be listed for disconnect scan")
	}
}
