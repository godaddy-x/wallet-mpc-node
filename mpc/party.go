package mpc

import "sort"

// SortedNodeIDs 稳定排序节点 ID（Alice 使用字符串 peer ID）。
func SortedNodeIDs(nodeIDs []string) []string {
	out := append([]string(nil), nodeIDs...)
	sort.Strings(out)
	return out
}

// IndexOf 返回 nodeID 在 sorted 列表中的下标。
func IndexOf(sorted []string, nodeID string) int {
	for i, id := range sorted {
		if id == nodeID {
			return i
		}
	}
	return -1
}

// ThresholdFromNodeCount walletMode 3→2, 5→3。
func ThresholdFromNodeCount(n int) uint32 {
	if n >= 5 {
		return 3
	}
	return 2
}
