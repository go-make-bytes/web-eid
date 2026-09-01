package audit

import (
	"context"
	"time"

	"azugo.io/core"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
)

// drainTask runs the gdpr client's background outbox delivery as a core.Tasker,
// so it integrates with the engine's azugo lifecycle (started on boot, stopped +
// flushed on shutdown) without an App.Start/Stop override.
type drainTask struct {
	client *gdpr.Client
}

// NewDrainTask returns a Tasker that drains buffered access records in the
// background and flushes them on shutdown.
func NewDrainTask(client *gdpr.Client) core.Tasker {
	return &drainTask{client: client}
}

func (t *drainTask) Name() string { return "gdpr-audit-drain" }

func (t *drainTask) Start(ctx context.Context) error {
	go t.client.Drain(ctx)

	return nil
}

func (t *drainTask) Stop() {
	// Close stops the drainer and flushes the outbox, bounded by a fresh context
	// (the app's background context may already be cancelled on shutdown).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = t.client.Close(ctx)
}
