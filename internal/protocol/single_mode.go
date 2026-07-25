package protocol

import "github.com/godaddy-x/wallet-mpc-node/types"

// isSingleKeygenStart 与 broker IsSingleKeyMode 对齐：threshold=1 且仅 1 个参与节点。
func isSingleKeygenStart(start types.CliMPCKeygenStartRes) bool {
	return start.Threshold == 1 && len(start.NodeIDs) == 1
}

// isSingleSignStart 与 broker IsSingleKeyMode 对齐：threshold=1 且签名参与集为单节点。
func isSingleSignStart(start types.CliMPCSignStartRes) bool {
	if start.Threshold != 1 || len(start.SignNodeIDs) != 1 {
		return false
	}
	if len(start.AllNodeIDs) == 0 {
		return true
	}
	return len(start.AllNodeIDs) == 1
}
