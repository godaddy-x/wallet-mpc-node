package alg_ed25519

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	dkgpkg "github.com/getamis/alice/crypto/tss/dkg"
	mpced25519 "github.com/godaddy-x/wallet-mpc-node/mpc/ed25519"
)

type PubJSON struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type BkJSON struct {
	X    string `json:"x"`
	Rank uint32 `json:"rank"`
}

func curve() elliptic.Curve {
	return elliptic.Ed25519()
}

func pubToJSON(p *ecpointgrouplaw.ECPoint) PubJSON {
	if p == nil {
		return PubJSON{}
	}
	return PubJSON{X: p.GetX().String(), Y: p.GetY().String()}
}

func pubFromJSON(j PubJSON) (*ecpointgrouplaw.ECPoint, error) {
	x, ok := new(big.Int).SetString(j.X, 10)
	if !ok {
		return nil, fmt.Errorf("frost: invalid pub x")
	}
	y, ok := new(big.Int).SetString(j.Y, 10)
	if !ok {
		return nil, fmt.Errorf("frost: invalid pub y")
	}
	return ecpointgrouplaw.NewECPoint(curve(), x, y)
}

func pubMapToJSON(m map[string]*ecpointgrouplaw.ECPoint) map[string]PubJSON {
	out := make(map[string]PubJSON, len(m))
	for id, p := range m {
		out[id] = pubToJSON(p)
	}
	return out
}

func pubMapFromJSON(m map[string]PubJSON) (map[string]*ecpointgrouplaw.ECPoint, error) {
	out := make(map[string]*ecpointgrouplaw.ECPoint, len(m))
	for id, j := range m {
		p, err := pubFromJSON(j)
		if err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, nil
}

func bksToJSON(m map[string]*birkhoffinterpolation.BkParameter) map[string]BkJSON {
	out := make(map[string]BkJSON, len(m))
	for id, bk := range m {
		out[id] = BkJSON{X: bk.GetX().String(), Rank: bk.GetRank()}
	}
	return out
}

func bksFromJSON(m map[string]BkJSON) (map[string]*birkhoffinterpolation.BkParameter, error) {
	out := make(map[string]*birkhoffinterpolation.BkParameter, len(m))
	for id, j := range m {
		x, ok := new(big.Int).SetString(j.X, 10)
		if !ok {
			return nil, fmt.Errorf("frost: invalid bk x for %s", id)
		}
		out[id] = birkhoffinterpolation.NewBkParameter(x, j.Rank)
	}
	return out, nil
}

func dkgResultFromPersist(data *NodeShareData) (*dkgpkg.Result, error) {
	if data == nil {
		return nil, fmt.Errorf("frost: nil share data")
	}
	pub, err := pubFromJSON(PubJSON{X: data.PubX, Y: data.PubY})
	if err != nil {
		return nil, err
	}
	share, ok := new(big.Int).SetString(data.Share, 10)
	if !ok {
		return nil, fmt.Errorf("frost: invalid share")
	}
	bks, err := bksFromJSON(data.Bks)
	if err != nil {
		return nil, err
	}
	ys, err := pubMapFromJSON(data.Ys)
	if err != nil {
		return nil, err
	}
	return &dkgpkg.Result{
		PublicKey: pub,
		Share:     share,
		Bks:       bks,
		Ys:        ys,
	}, nil
}

// RootPubHexFromShareData 32 字节 Ed25519 公钥 hex。
func RootPubHexFromShareData(data *NodeShareData) (string, error) {
	if data == nil {
		return "", fmt.Errorf("frost: nil share data")
	}
	if data.PubHex != "" {
		return data.PubHex, nil
	}
	pub, err := pubFromJSON(PubJSON{X: data.PubX, Y: data.PubY})
	if err != nil {
		return "", err
	}
	return PubHexFromPoint(pub)
}

func PubHexFromPoint(pub *ecpointgrouplaw.ECPoint) (string, error) {
	b, err := mpced25519.EncodeEd25519PubKey(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
