package alg_ed25519

import (
	"fmt"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
)

func FilterParticipantMaps(
	participants []string,
	selfID string,
	bks map[string]*birkhoffinterpolation.BkParameter,
	ys map[string]*ecpointgrouplaw.ECPoint,
) (map[string]*birkhoffinterpolation.BkParameter, map[string]*ecpointgrouplaw.ECPoint, error) {
	want := make(map[string]struct{}, len(participants))
	for _, id := range participants {
		want[id] = struct{}{}
	}
	if _, ok := want[selfID]; !ok {
		return nil, nil, fmt.Errorf("frost: self %s not in participants", selfID)
	}
	outBK := make(map[string]*birkhoffinterpolation.BkParameter, len(participants))
	outY := make(map[string]*ecpointgrouplaw.ECPoint, len(participants))
	for id := range want {
		bk, ok := bks[id]
		if !ok {
			return nil, nil, fmt.Errorf("frost: missing bk for %s", id)
		}
		y, ok := ys[id]
		if !ok {
			return nil, nil, fmt.Errorf("frost: missing Y for %s", id)
		}
		outBK[id] = bk
		outY[id] = y
	}
	return outBK, outY, nil
}
