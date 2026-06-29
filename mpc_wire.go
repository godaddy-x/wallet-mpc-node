package main

import (
	"fmt"
	"strings"
	"sync"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

var mpcKeySessionLocks sync.Map // keyID|participants -> *sync.Mutex

func mpcKeySessionLock(keyID string, participants []string) *sync.Mutex {
	key := keyID + "|" + strings.Join(mpc.SortedNodeIDs(participants), ",")
	v, _ := mpcKeySessionLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func sendMPCProtocolWire(wsClient *sdk.SocketSDK, taskID, module string, myIndex int, targetNodeID, wireB64 string) error {
	var data []byte
	var err error
	switch module {
	case "keygen":
		payload := &dto.CliMPCKeygenMsgRes{
			TaskID:          taskID,
			WireBytesBase64: wireB64,
			FromIndex:       myIndex,
			IsBroadcast:     true,
		}
		data, err = utils.JsonMarshal(payload)
	case "sign":
		payload := &dto.CliMPCSignMsgRes{
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
	publicKey, err := getTempPublicKey(module, targetNodeID, taskID)
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
	req := &dto.CliMPCEncryptData{TaskID: taskID, Subject: targetNodeID, Data: utils.Base64Encode(encrypt)}
	switch module {
	case "keygen":
		return sendKeygenProtocolMsgWithRetry(wsClient, req, mpcProtocolSendMaxAttempts)
	case "sign":
		return sendSignProtocolMsgWithRetry(wsClient, req, mpcProtocolSendMaxAttempts)
	default:
		return nil
	}
}
