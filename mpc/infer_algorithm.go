package mpc

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// InferAlgorithmFromPubHex 根据根公钥 hex 推断 MPC 算法（65B uncompressed → ECDSA；32B → Ed25519）。
func InferAlgorithmFromPubHex(pubHex string) (Algorithm, error) {
	b, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil {
		return "", fmt.Errorf("invalid root pub hex: %w", err)
	}
	switch {
	case len(b) == 65 && b[0] == 0x04:
		return AlgECDSA, nil
	case len(b) == 32:
		return AlgEd25519, nil
	default:
		return "", fmt.Errorf("cannot infer algorithm from pub hex length %d", len(b))
	}
}

// InferAlgorithmFromPubHexOptionalPrefix 同 InferAlgorithmFromPubHex，允许 0x 前缀。
func InferAlgorithmFromPubHexOptionalPrefix(pubHex string) (Algorithm, error) {
	s := strings.TrimPrefix(strings.TrimSpace(pubHex), "0x")
	return InferAlgorithmFromPubHex(s)
}

// AssertPubHexMatchesAlgorithm 校验公钥格式与声明算法一致。
func AssertPubHexMatchesAlgorithm(alg Algorithm, pubHex string) error {
	inferred, err := InferAlgorithmFromPubHex(pubHex)
	if err != nil {
		return err
	}
	if inferred != alg {
		return fmt.Errorf("algorithm %q does not match pub hex format (expected %q)", alg, inferred)
	}
	return nil
}
