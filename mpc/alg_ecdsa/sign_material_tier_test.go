package alg_ecdsa

import "testing"

func TestMaterialUseTierForCount(t *testing.T) {
	cases := []struct {
		uses int
		want MaterialUseTier
	}{
		{1, TierNormal},
		{39, TierNormal},
		{40, TierWarmInfo},
		{55, TierWarmInfo},
		{56, TierWarmWarn},
		{63, TierWarmWarn},
		{64, TierSyncWait},
	}
	for _, tc := range cases {
		if got := MaterialUseTierForCount(tc.uses); got != tc.want {
			t.Fatalf("uses=%d got tier=%d want=%d", tc.uses, got, tc.want)
		}
	}
}
