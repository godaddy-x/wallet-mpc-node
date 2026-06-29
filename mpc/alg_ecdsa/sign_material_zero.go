package alg_ecdsa

import (
	"crypto/subtle"
	"math/big"

	refreshpkg "github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
)

func zeroBigInt(x *big.Int) {
	if x == nil {
		return
	}
	b := x.Bytes()
	for i := range b {
		b[i] = 0
	}
	x.SetInt64(0)
}

// zeroRefreshResult 显式清零 refresh 结果中的秘密材料（替换前调用）。
func zeroRefreshResult(r *refreshpkg.Result) {
	if r == nil {
		return
	}
	zeroBigInt(r.Share)
	zeroBigInt(r.YSecret)
	if r.PaillierKey != nil {
		p, q := r.PaillierKey.GetPQ()
		zeroBigInt(p)
		zeroBigInt(q)
	}
	_ = subtle.ConstantTimeCompare([]byte{0}, []byte{0})
}
