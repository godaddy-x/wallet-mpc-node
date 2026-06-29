package mpc

import (
	"fmt"
	"sync/atomic"

	"github.com/getamis/alice/types"
)

// AliceListener 实现 Alice StateChangedListener。
type AliceListener struct {
	errCh      chan error
	failLabel  string
	detail     atomic.Value // string
}

// NewAliceListener failLabel 用于失败消息前缀，例如 "cggmp" / "frost"。
func NewAliceListener(failLabel string) *AliceListener {
	return &AliceListener{
		errCh:     make(chan error, 1),
		failLabel: failLabel,
	}
}

func (l *AliceListener) NoteFailure(reason string) {
	if reason != "" {
		l.detail.Store(reason)
	}
}

func (l *AliceListener) FailureDetail() string {
	if v := l.detail.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (l *AliceListener) OnStateChanged(oldState, newState types.MainState) {
	switch newState {
	case types.StateFailed:
		msg := fmt.Sprintf("alice %s failed: %s -> %s", l.failLabel, oldState, newState)
		if d := l.FailureDetail(); d != "" {
			msg = msg + ": " + d
		} else if d := LastAliceProtocolLog(); d != "" {
			msg = msg + ": " + d
		}
		select {
		case l.errCh <- fmt.Errorf("%s", msg):
		default:
		}
	case types.StateDone:
		select {
		case l.errCh <- nil:
		default:
		}
	}
}

func (l *AliceListener) Done() <-chan error {
	return l.errCh
}
