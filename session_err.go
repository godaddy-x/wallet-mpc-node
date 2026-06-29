package main

import (
	"time"
)

// deliverSessionErr 将致命错误送入 errCh；不静默丢弃（TSS 发送/Update 失败须让主循环尽快退出）。
func deliverSessionErr(errCh chan error, err error) {
	if err == nil || errCh == nil {
		return
	}
	for {
		select {
		case errCh <- err:
			return
		default:
			// 腾出 errCh 空间，避免 default 分支丢错误导致对端永久等待。
			select {
			case <-errCh:
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
}
