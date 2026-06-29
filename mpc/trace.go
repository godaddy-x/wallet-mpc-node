package mpc

import (
	"fmt"
	"strings"
	"sync/atomic"
)

var lastAliceProtocolLog atomic.Value // string

// RecordAliceProtocolLog 记录 Alice messageLoop 的 Warn/Error 日志，供失败时回显。
func RecordAliceProtocolLog(msg string, ctx []interface{}) {
	if strings.TrimSpace(msg) == "" {
		return
	}
	line := msg
	if len(ctx) > 0 {
		line = fmt.Sprintf("%s %v", msg, ctx)
	}
	lastAliceProtocolLog.Store(line)
}

// LastAliceProtocolLog 返回最近一次 Alice 协议 Warn/Error 文本。
func LastAliceProtocolLog() string {
	if v := lastAliceProtocolLog.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ClearAliceProtocolLog 清空协议失败追踪。
func ClearAliceProtocolLog() {
	lastAliceProtocolLog.Store("")
}
