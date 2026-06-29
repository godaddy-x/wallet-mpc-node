package mpc

import (
	"context"
	"fmt"
	"time"

	"github.com/getamis/alice/types"
)

func addMessageToBackend(label string, backend types.MessageMain, listener *AliceListener, msg types.Message) error {
	if backend == nil || msg == nil {
		return fmt.Errorf("%s: nil backend or message", label)
	}
	senderID := msg.GetId()
	if senderID == "" {
		return fmt.Errorf("%s: empty message sender id", label)
	}
	err := backend.AddMessage(senderID, msg)
	if err != nil {
		listener.NoteFailure(fmt.Sprintf("AddMessage from %s type=%d: %v", senderID, msg.GetMessageType(), err))
	}
	return err
}

// RunAliceBackend 启动 Alice 协议并等待完成；listener 须与 NewDKG/NewRefresh/NewSign 传入的为同一实例。
func RunAliceBackend(ctx context.Context, backend types.MessageMain, inbox *Inbox, listener *AliceListener, timeout time.Duration, label string) error {
	if backend == nil || inbox == nil || listener == nil {
		return fmt.Errorf("%s: nil backend, inbox or listener", label)
	}
	if err := inbox.SetHandler(func(_ string, msg types.Message) error {
		return addMessageToBackend(label, backend, listener, msg)
	}); err != nil {
		return fmt.Errorf("%s: replay buffered messages: %w", label, err)
	}
	backend.Start()
	defer func() {
		backend.Stop()
		inbox.ClearHandler()
	}()

	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-listener.Done():
		if err != nil {
			return err
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("%s: protocol timeout after %s", label, timeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}
