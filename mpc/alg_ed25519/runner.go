package alg_ed25519

import (
	"context"
	"time"

	"github.com/getamis/alice/types"
	"github.com/godaddy-x/wallet-mpc-node/mpc"
)

type MessageBackend interface {
	types.MessageMain
}

func RunBackend(ctx context.Context, backend MessageBackend, inbox *Inbox, listener *mpc.AliceListener, timeout time.Duration) error {
	return mpc.RunAliceBackend(ctx, backend, inbox, listener, timeout, algLabel)
}
