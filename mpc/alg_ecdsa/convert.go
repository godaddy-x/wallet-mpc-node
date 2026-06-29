package alg_ecdsa

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	dkgpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	zkPaillier "github.com/getamis/alice/crypto/zkproof/paillier"
)

// PubJSON 可序列化 EC 点。
type PubJSON struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// BkJSON Birkhoff 参数。
type BkJSON struct {
	X    string `json:"x"`
	Rank uint32 `json:"rank"`
}

// PaillierKeyJSON Paillier 私钥素因子（refresh 输出）。
type PaillierKeyJSON struct {
	P string `json:"p"`
	Q string `json:"q"`
}

// PedJSON Pedersen 公开参数。
type PedJSON struct {
	N string `json:"n"`
	S string `json:"s"`
	T string `json:"t"`
}

func curve() elliptic.Curve {
	return elliptic.Secp256k1()
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
		return nil, fmt.Errorf("ecdsa: invalid pub x")
	}
	y, ok := new(big.Int).SetString(j.Y, 10)
	if !ok {
		return nil, fmt.Errorf("ecdsa: invalid pub y")
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
			return nil, fmt.Errorf("ecdsa: invalid bk x for %s", id)
		}
		out[id] = birkhoffinterpolation.NewBkParameter(x, j.Rank)
	}
	return out, nil
}

func dkgResultFromPersist(data *NodeShareData) (*dkgpkg.Result, error) {
	if data == nil {
		return nil, fmt.Errorf("ecdsa: nil share data")
	}
	pub, err := pubFromJSON(PubJSON{X: data.PubX, Y: data.PubY})
	if err != nil {
		return nil, err
	}
	share, ok := new(big.Int).SetString(data.Share, 10)
	if !ok {
		return nil, fmt.Errorf("ecdsa: invalid share")
	}
	rid, err := hex.DecodeString(data.Rid)
	if err != nil {
		return nil, err
	}
	bks, err := bksFromJSON(data.Bks)
	if err != nil {
		return nil, err
	}
	return &dkgpkg.Result{
		PublicKey: pub,
		Share:     share,
		Bks:       bks,
		Rid:       rid,
	}, nil
}

// RefreshPersist 可序列化的 refresh 输出（用于内存缓存克隆）。
type RefreshPersist struct {
	Share      string              `json:"share"`
	Paillier   PaillierKeyJSON     `json:"paillier"`
	PartialPub map[string]PubJSON  `json:"partialPub"`
	Ped        map[string]PedJSON  `json:"ped"`
}

func refreshResultToPersist(r *refreshpkg.Result) (*RefreshPersist, error) {
	if r == nil || r.PaillierKey == nil {
		return nil, fmt.Errorf("ecdsa: nil refresh result")
	}
	p, q := r.PaillierKey.GetPQ()
	if p == nil || q == nil {
		return nil, fmt.Errorf("ecdsa: invalid paillier pq")
	}
	ped := make(map[string]PedJSON, len(r.PedParameter))
	for id, pp := range r.PedParameter {
		if pp == nil {
			continue
		}
		ped[id] = PedJSON{
			N: pp.GetN().String(),
			S: pp.GetS().String(),
			T: pp.GetT().String(),
		}
	}
	return &RefreshPersist{
		Share:      r.Share.String(),
		Paillier:   PaillierKeyJSON{P: p.String(), Q: q.String()},
		PartialPub: pubMapToJSON(r.PartialPubKey),
		Ped:        ped,
	}, nil
}

func refreshResultFromPersist(share string, paillierJSON PaillierKeyJSON, partial map[string]PubJSON, ped map[string]PedJSON) (*refreshpkg.Result, error) {
	r := &refreshpkg.Result{
		PartialPubKey: make(map[string]*ecpointgrouplaw.ECPoint),
		PedParameter:  make(map[string]*zkPaillier.PederssenOpenParameter),
	}
	s, ok := new(big.Int).SetString(share, 10)
	if !ok {
		return nil, fmt.Errorf("ecdsa: invalid refresh share")
	}
	r.Share = s
	p, ok := new(big.Int).SetString(paillierJSON.P, 10)
	if !ok {
		return nil, fmt.Errorf("ecdsa: invalid paillier p")
	}
	q, ok := new(big.Int).SetString(paillierJSON.Q, 10)
	if !ok {
		return nil, fmt.Errorf("ecdsa: invalid paillier q")
	}
	var err error
	r.PaillierKey, err = paillier.NewPaillierWithGivenPrimes(p, q)
	if err != nil {
		return nil, err
	}
	r.PartialPubKey, err = pubMapFromJSON(partial)
	if err != nil {
		return nil, err
	}
	for id, pj := range ped {
		n, ok := new(big.Int).SetString(pj.N, 10)
		if !ok {
			return nil, fmt.Errorf("ecdsa: invalid ped n")
		}
		sv, ok := new(big.Int).SetString(pj.S, 10)
		if !ok {
			return nil, fmt.Errorf("ecdsa: invalid ped s")
		}
		t, ok := new(big.Int).SetString(pj.T, 10)
		if !ok {
			return nil, fmt.Errorf("ecdsa: invalid ped t")
		}
		r.PedParameter[id] = zkPaillier.NewPedersenOpenParameter(n, sv, t)
	}
	return r, nil
}

func cloneRefreshResult(r *refreshpkg.Result) (*refreshpkg.Result, error) {
	p, err := refreshResultToPersist(r)
	if err != nil {
		return nil, err
	}
	return refreshResultFromPersist(p.Share, p.Paillier, p.PartialPub, p.Ped)
}
