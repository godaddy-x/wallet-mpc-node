// 弱机/线上环境：TSS 协议消息的缓冲、WS 超时与 recvCh 背压参数。
package main

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

const (
	// party.Update 向 outCh 写消息；若发送协程因 WS/ML-KEM 慢而阻塞，小 buffer 会反压卡死 Update。
	mpcTssOutChBuf = 128
	// 单轮 burst + 慢 Update 时避免 recvCh 被填满后丢消息。
	mpcTssRecvChBuf = 1024
	// 协议消息 WS 单次超时（秒）；弱机 ML-KEM 加密 + 网络 RTT 可能 >2s。
	mpcProtocolWSReqSec        = 15
	mpcProtocolSendMaxAttempts = 5
	// recvCh 满时周期性打日志，但不丢弃（TSS 丢一条即死锁）。
	mpcRecvChWaitLogSec = 30
)

func mpcProtocolSendBackoff() []time.Duration {
	return []time.Duration{
		200 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		3 * time.Second,
	}
}

func sendMpcProtocolMsgWithRetry(wsClient *sdk.SocketSDK, route string, req *dto.CliMPCEncryptData, maxAttempts int) error {
	if wsClient == nil || req == nil {
		return errors.New("sendMpcProtocolMsgWithRetry invalid argument")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	backoff := mpcProtocolSendBackoff()
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		var res dto.CliMPCResultRes
		err := wsClient.SendWebSocketMessage(route, req, &res, true, true, mpcProtocolWSReqSec)
		if err == nil && res.OK {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("server returned OK=false for " + route)
		}
		if i < maxAttempts {
			sleep := backoff[i-1]
			if i-1 >= len(backoff) {
				sleep = backoff[len(backoff)-1]
			}
			time.Sleep(sleep)
		}
	}
	return lastErr
}

type outboundSender struct {
	pendingSend  atomic.Int32
	done         chan struct{}
	firstSendErr atomic.Pointer[error]
}

func (s *outboundSender) noteSendErr(err error) {
	if err == nil || s == nil {
		return
	}
	e := err
	s.firstSendErr.CompareAndSwap(nil, &e)
}

func (s *outboundSender) FirstSendErr() error {
	if s == nil {
		return nil
	}
	if p := s.firstSendErr.Load(); p != nil {
		return *p
	}
	return nil
}

func (s *outboundSender) Pending() int32 {
	if s == nil {
		return 0
	}
	return s.pendingSend.Load()
}

// WaitDone 等待 outCh 关闭后 send 队列全部发完。timeout<=0 表示一直等到发完。
func (s *outboundSender) WaitDone(timeout time.Duration) error {
	if s == nil || s.done == nil {
		return nil
	}
	if timeout <= 0 {
		<-s.done
		return nil
	}
	select {
	case <-s.done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("outCh sender drain timeout, pending=%d", s.Pending())
	}
}

func drainOutSender(sender *outboundSender) {
	if sender != nil {
		_ = sender.WaitDone(0)
	}
}
