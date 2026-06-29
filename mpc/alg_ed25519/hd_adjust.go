package alg_ed25519

import (
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

func AdjustShareAndPubKeyForPath(
	share *big.Int,
	rootPub *ecpointgrouplaw.ECPoint,
	keyID string,
	accountIndex, change, addrIndex uint32,
) (adjustedShare *big.Int, childPub *ecpointgrouplaw.ECPoint, delta *big.Int, err error) {
	if share == nil || rootPub == nil {
		return nil, nil, nil, fmt.Errorf("frost: nil share or pubkey")
	}
	rootPubHex, err := PubHexFromPoint(rootPub)
	if err != nil {
		return nil, nil, nil, err
	}
	path := hd.PathFromAccountAndAddress(accountIndex, change, addrIndex)
	pathDelta, childHex, err := hd.DeriveEd25519ChildPubFromPath(rootPubHex, hd.ChainCodeFromKeyID(keyID), path)
	if err != nil {
		return nil, nil, nil, err
	}
	childPt, err := PointFromPubHex(childHex)
	if err != nil {
		return nil, nil, nil, err
	}
	n := hd.Ed25519Order()
	adj := new(big.Int).Add(new(big.Int).Set(share), pathDelta)
	adj.Mod(adj, n)
	return adj, childPt, new(big.Int).Set(pathDelta), nil
}

func AdjustYsForDelta(
	ys map[string]*ecpointgrouplaw.ECPoint,
	delta *big.Int,
) (map[string]*ecpointgrouplaw.ECPoint, error) {
	if delta == nil || delta.Sign() == 0 {
		return ys, nil
	}
	if len(ys) == 0 {
		return ys, nil
	}
	deltaG := ecpointgrouplaw.ScalarBaseMult(curve(), delta)
	out := make(map[string]*ecpointgrouplaw.ECPoint, len(ys))
	for id, p := range ys {
		if p == nil {
			return nil, fmt.Errorf("frost: nil Y for %s", id)
		}
		adj, err := p.Add(deltaG)
		if err != nil {
			return nil, err
		}
		out[id] = adj
	}
	return out, nil
}

func PointFromPubHex(pubHex string) (*ecpointgrouplaw.ECPoint, error) {
	x, y, err := hd.Ed25519XYFromPubHex(pubHex)
	if err != nil {
		return nil, err
	}
	return ecpointgrouplaw.NewECPoint(curve(), x, y)
}
