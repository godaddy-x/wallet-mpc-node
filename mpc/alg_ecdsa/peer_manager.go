package alg_ecdsa

import (
	"fmt"

	dkgmsg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	refreshmsg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	signmsg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/sign"
	"github.com/getamis/alice/types"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
	"google.golang.org/protobuf/proto"
)

const algLabel = "ecdsa"

type SendWireFunc = mpc.SendWireFunc
type WSPeerManager = mpc.WSPeerManager
type Inbox = mpc.Inbox

func NewWSPeerManager(selfID string, allNodeIDs []string, send SendWireFunc) *WSPeerManager {
	return mpc.NewWSPeerManager(selfID, allNodeIDs, send, moduleForProto, algLabel)
}

func NewInbox() *Inbox {
	return mpc.NewInbox(algLabel, unmarshalWire)
}

func moduleForProto(msg proto.Message) (byte, error) {
	switch msg.(type) {
	case *dkgmsg.Message:
		return WireModuleDKG, nil
	case *refreshmsg.Message:
		return WireModuleRefresh, nil
	case *signmsg.Message:
		return WireModuleSign, nil
	default:
		return 0, fmt.Errorf("%s: unknown proto type %T", algLabel, msg)
	}
}

var errUnknownWireModule = fmt.Errorf("%s: unknown wire module", algLabel)

func unmarshalWire(mod byte, raw []byte) (types.Message, error) {
	switch mod {
	case WireModuleDKG:
		m := &dkgmsg.Message{}
		if err := proto.Unmarshal(raw, m); err != nil {
			return nil, err
		}
		return m, nil
	case WireModuleRefresh:
		m := &refreshmsg.Message{}
		if err := proto.Unmarshal(raw, m); err != nil {
			return nil, err
		}
		return m, nil
	case WireModuleSign:
		m := &signmsg.Message{}
		if err := proto.Unmarshal(raw, m); err != nil {
			return nil, err
		}
		return m, nil
	default:
		return nil, errUnknownWireModule
	}
}
