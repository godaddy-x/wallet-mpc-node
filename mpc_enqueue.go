package main

import (
	"sync"
	"time"
)

// enqueueRecvItem 向 TSS recvCh 投递消息；满则阻塞等待，仅在 session 关闭时放弃。
func enqueueRecvItem(recvCh chan recvItem, closed *bool, closedMu *sync.Mutex, waitLog func(), item recvItem) bool {
	wait := time.Duration(mpcRecvChWaitLogSec) * time.Second
	for {
		closedMu.Lock()
		if *closed {
			closedMu.Unlock()
			return false
		}
		closedMu.Unlock()
		select {
		case recvCh <- item:
			return true
		case <-time.After(wait):
			waitLog()
		}
	}
}
