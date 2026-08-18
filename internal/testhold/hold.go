// Package testhold 提供联调/集成测试用的任务处理延迟（仅通过环境变量开启）。
package testhold

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// Duration 读取 MPC_TEST_TASK_HOLD_MS（毫秒）；未设置或 <=0 时返回 0。
func Duration() time.Duration {
	ms, err := strconv.Atoi(strings.TrimSpace(os.Getenv("MPC_TEST_TASK_HOLD_MS")))
	if err != nil || ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// Sleep 在任务处理路径中人为拉长耗时，便于 kill-node fast-fail 联调。
// abortCtx / isAborted 非空时提前退出，避免 abort 后仍阻塞。
func Sleep(taskID string, abortCtx context.Context, isAborted func(string) bool) {
	hold := Duration()
	if hold <= 0 {
		return
	}
	deadline := time.Now().Add(hold)
	tick := 50 * time.Millisecond
	for time.Now().Before(deadline) {
		if isAborted != nil && isAborted(taskID) {
			return
		}
		if abortCtx != nil {
			select {
			case <-abortCtx.Done():
				return
			default:
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		if remaining < tick {
			tick = remaining
		}
		time.Sleep(tick)
	}
}
