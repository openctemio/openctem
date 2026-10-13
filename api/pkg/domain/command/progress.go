package command

// Per-command progress and stall detection (research/122): a heartbeat
// reports how many of each held command's targets are finished; the
// platform keeps the last time that number grew. A running task is
// re-queued when it finished no target for its stall window (it is stuck),
// or when it runs far past its task budget (the sensor should have stopped
// it at twice its budget; this is the backstop). A slow but progressing
// task is never re-queued before that.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Progress is one command's progress as a heartbeat reports it, untrusted.
type Progress struct {
	Done  int
	Total int
}

// MaxProgressEntries bounds the progress entries one heartbeat records.
const MaxProgressEntries = 1000

// OverrunGraceSeconds is how long past twice its task budget a running
// command may go before the platform takes it back: the sensor stops it at
// twice its budget, and its result needs time to arrive.
const OverrunGraceSeconds = 300

// Messages a re-queued command records (command_events, the task's error).
const (
	StalledMessage = "re-queued: the task finished no target within its stall window (the tool or its targets stopped answering)"
	OverrunMessage = "re-queued: the task ran past twice its time budget and did not report"
)

// ProgressRecorder records the progress a sensor's heartbeat reports for
// the commands it holds. Only commands of tenantID held by sensorID
// (acknowledged or running) are touched; done never decreases and never
// exceeds the command's own target count, whatever the sensor sends.
type ProgressRecorder interface {
	RecordProgress(ctx context.Context, tenantID, sensorID shared.ID, progress map[string]Progress) (int64, error)
}

// StallReaper re-queues running commands that stalled or overran their
// budget (one more dispatch attempt each, like a lost lease).
type StallReaper interface {
	RequeueStalledCommands(ctx context.Context) ([]RequeuedCommand, error)
}
