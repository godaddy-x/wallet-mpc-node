package alg_ecdsa

import (
	"fmt"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
)

// FilterParticipantMaps 将 DKG 元数据裁剪到本次在线参与签名的节点集合。
func FilterParticipantMaps(
	participants []string,
	selfID string,
	bks map[string]*birkhoffinterpolation.BkParameter,
	partialPub map[string]*ecpointgrouplaw.ECPoint,
) (map[string]*birkhoffinterpolation.BkParameter, map[string]*ecpointgrouplaw.ECPoint, error) {
	want := make(map[string]struct{}, len(participants))
	for _, id := range participants {
		want[id] = struct{}{}
	}
	if _, ok := want[selfID]; !ok {
		return nil, nil, fmt.Errorf("ecdsa: self %s not in participants", selfID)
	}
	outBK := make(map[string]*birkhoffinterpolation.BkParameter, len(participants))
	outPP := make(map[string]*ecpointgrouplaw.ECPoint, len(participants))
	for id := range want {
		bk, ok := bks[id]
		if !ok {
			return nil, nil, fmt.Errorf("ecdsa: missing bk for %s", id)
		}
		pp, ok := partialPub[id]
		if !ok {
			return nil, nil, fmt.Errorf("ecdsa: missing partial pub for %s", id)
		}
		outBK[id] = bk
		outPP[id] = pp
	}
	return outBK, outPP, nil
}
