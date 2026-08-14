package protocol

import (
	"fmt"
	"github.com/godaddy-x/wallet-mpc-node/internal/tempkey"
	"strings"
	"sync"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/client/ws"
	"github.com/godaddy-x/freego/core/str"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/types"
)

var mpcKeySessionLocks sync.Map // keyID|participants -> *sync.Mutex

func mpcKeySessionLock(keyID string, participants []string) *sync.Mutex {
	key := keyID + "|" + strings.Join(mpc.SortedNodeIDs(participants), ",")
	v, _ := mpcKeySessionLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func sendMPCProtocolWire(wsClient *ws.SDK, taskID, module string, myIndex int, targetNodeID, wireB64 string) error {
	var data []byte
	var err error
	switch module {
	case "keygen":
		payload := &types.CliMPCKeygenMsgRes{
			TaskID:          taskID,
			WireBytesBase64: wireB64,
			FromIndex:       myIndex,
			IsBroadcast:     true,
		}
		data, err = utils.JsonMarshal(payload)
	case "sign":
		payload := &types.CliMPCSignMsgRes{
			TaskID:          taskID,
			WireBytesBase64: wireB64,
			FromIndex:       myIndex,
			IsBroadcast:     true,
		}
		data, err = utils.JsonMarshal(payload)
	default:
		return fmt.Errorf("unknown mpc router module %s", module)
	}
	if err != nil {
		return err
	}
	publicKey, err := tempkey.PeerPublicKey(module, targetNodeID, taskID)
	if err != nil {
		return err
	}
	if len(publicKey) == 0 {
		return fmt.Errorf("no temp public key for target %s", targetNodeID)
	}
	aadSuffix := "mpcKeygenMsg"
	if module == "sign" {
		aadSuffix = "mpcSignMsg"
	}
	encrypt, err := ecc.EncryptMLKEM1024(publicKey, data, utils.Str2Bytes(utils.AddStr(taskID, "|", targetNodeID, "|", aadSuffix)))
	if err != nil {
		return err
	}
	req := &types.CliMPCEncryptData{TaskID: taskID, Subject: targetNodeID, Data: utils.Base64Encode(encrypt)}
	switch module {
	case "keygen":
		return sendKeygenProtocolMsgWithRetry(wsClient, req, mpcProtocolSendMaxAttempts)
	case "sign":
		return sendSignProtocolMsgWithRetry(wsClient, req, mpcProtocolSendMaxAttempts)
	default:
		return nil
	}
}
