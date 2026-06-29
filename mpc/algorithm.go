// Package mpc 提供 MPC 多算法支持的公共类型与常量。
// ECDSA 实现为 getamis/alice CGGMP（mpc/alg_ecdsa），公钥 HD 派生在 mpc/hd，链上验签在 mpc/ecdsa。
// Ed25519 实现为 getamis/alice FROST（mpc/alg_ed25519），HD 在 mpc/hd/ed25519.go，验签在 mpc/ed25519。
//
//   - mpc/alg_ecdsa：Alice CGGMP (t,n) 门限 ECDSA
//   - mpc/alg_ed25519：Alice FROST (t,n) 门限 Ed25519
//   - mpc/hd：无 seed 公钥派生（wallet / account / address）
//   - mpc/ecdsa：ECDSA 验签工具
//   - mpc/ed25519：Ed25519 验签工具
package mpc

import (
	"fmt"
	"strings"
)

// Algorithm 表示 MPC 使用的签名算法。
type Algorithm string

const (
	// AlgECDSA secp256k1 ECDSA 门限签名（CGGMP 实现，算法标识仍为 ecdsa）
	AlgECDSA Algorithm = "ecdsa"
	// AlgEd25519 Ed25519 门限签名（FROST 实现）
	AlgEd25519 Algorithm = "ed25519"
)

// ParseAlgorithm 解析并校验 MPC 算法标识（ecdsa | ed25519）。
func ParseAlgorithm(s string) (Algorithm, error) {
	switch Algorithm(strings.TrimSpace(strings.ToLower(s))) {
	case AlgECDSA, AlgEd25519:
		return Algorithm(strings.TrimSpace(strings.ToLower(s))), nil
	case "":
		return "", fmt.Errorf("mpc: algorithm required (ecdsa or ed25519)")
	default:
		return "", fmt.Errorf("mpc: unsupported algorithm %q", s)
	}
}
