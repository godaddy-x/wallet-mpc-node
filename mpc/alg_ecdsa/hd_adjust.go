package alg_ecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/godaddy-x/wallet-mpc-node/mpc/hd"
)

// AdjustShareAndPubKeyForPath 对非硬化 HD 路径调整 share 与签名公钥。
// 返回 delta 供同步调整 partialPubKey（CGGMP sign 要求 share / pubKey / partialPub 一致）。
func AdjustShareAndPubKeyForPath(
	share *big.Int,
	rootPub *ecpointgrouplaw.ECPoint,
	keyID string,
	accountIndex, change, addrIndex uint32,
) (adjustedShare *big.Int, childPub *ecpointgrouplaw.ECPoint, delta *big.Int, err error) {
	if share == nil || rootPub == nil {
		return nil, nil, nil, fmt.Errorf("ecdsa: nil share or pubkey")
	}
	rootECDSA := &ecdsa.PublicKey{
		Curve: hd.S256(),
		X:     new(big.Int).Set(rootPub.GetX()),
		Y:     new(big.Int).Set(rootPub.GetY()),
	}
	path := hd.PathFromAccountAndAddress(accountIndex, change, addrIndex)
	pathDelta, child, err := hd.DeriveChildPubFromPath(rootECDSA, hd.ChainCodeFromKeyID(keyID), path)
	if err != nil {
		return nil, nil, nil, err
	}
	n := hd.S256().Params().N
	adj := new(big.Int).Add(new(big.Int).Set(share), pathDelta)
	adj.Mod(adj, n)
	childPt, err := ecpointgrouplaw.NewECPoint(rootPub.GetCurve(), child.X, child.Y)
	if err != nil {
		return nil, nil, nil, err
	}
	return adj, childPt, new(big.Int).Set(pathDelta), nil
}

// AdjustPartialPubsForDelta 将公开派生 delta 加到各 partialPub（share' = share + delta 时配套调整）。
func AdjustPartialPubsForDelta(
	partialPub map[string]*ecpointgrouplaw.ECPoint,
	delta *big.Int,
) (map[string]*ecpointgrouplaw.ECPoint, error) {
	if delta == nil || delta.Sign() == 0 {
		return partialPub, nil
	}
	if len(partialPub) == 0 {
		return partialPub, nil
	}
	deltaG := ecpointgrouplaw.ScalarBaseMult(curve(), delta)
	out := make(map[string]*ecpointgrouplaw.ECPoint, len(partialPub))
	for id, p := range partialPub {
		if p == nil {
			return nil, fmt.Errorf("ecdsa: nil partial pub for %s", id)
		}
		adj, err := p.Add(deltaG)
		if err != nil {
			return nil, err
		}
		out[id] = adj
	}
	return out, nil
}
