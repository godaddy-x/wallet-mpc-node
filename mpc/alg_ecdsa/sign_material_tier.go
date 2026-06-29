package alg_ecdsa

// MaterialUseTier 材料使用次数分级（与 App 降级策略对齐）。
type MaterialUseTier int

const (
	TierNormal MaterialUseTier = iota
	TierWarmInfo
	TierWarmWarn
	TierSyncWait
)

// MaterialUseTierForCount 根据本次签名后的 uses 计数返回分级。
func MaterialUseTierForCount(useCount int) MaterialUseTier {
	switch {
	case useCount >= SignMaterialSyncWaitUses:
		return TierSyncWait
	case useCount >= SignMaterialWarnThreshold:
		return TierWarmWarn
	case useCount >= SignMaterialWarmThreshold:
		return TierWarmInfo
	default:
		return TierNormal
	}
}
