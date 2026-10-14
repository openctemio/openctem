package command

// Per-command progress and stall detection (research/122, research/125): a
// heartbeat reports how many of each held command's targets are finished
// and liveness counters (records and output bytes the tool delivered, CPU
// time of its processes); the platform keeps the last time any of them
// moved. A running task none of whose signals moved for its stall window
// is stalled: the platform asks its sensor to stop it and hand back what it
// finished (stop_command_ids), and re-queues it only when the sensor does
// not answer within StopGraceSeconds. A task that runs far past its task
// budget is re-queued at once (the sensor should have stopped it at twice
// its budget; this is the backstop). A slow but working task is never
// stopped before that. The signals are hints: faking them can only delay a
// stall decision, never the overrun cap or the run's deadline.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Progress is one command's progress as a heartbeat reports it, untrusted.
// Records, OutputBytes and CPUMs are monotonic liveness counters (0: not
// reported).
type Progress struct {
	Done        int
	Total       int
	Records     int64
	OutputBytes int64
	CPUMs       int64
	// ReleasedKeys are the host keys the holder freed because the targets
	// that needed them settled (research/130). Untrusted: only the keys of
	// the command itself count, for a command the sensor holds.
	ReleasedKeys []string
}

// MaxReleasedKeyLen bounds one released key a heartbeat may name (the
// sensor's bound on a host key).
const MaxReleasedKeyLen = 512

// MaxLivenessCounter bounds each liveness counter a heartbeat may set.
const MaxLivenessCounter = int64(1) << 50

// CPUMoveMs is how much a command's CPU time must grow, since it last
// counted, to count as the task moving: an idle or hung process still uses
// a little CPU.
const CPUMoveMs = 2000

// StopGraceSeconds is how long the platform waits, after asking a sensor to
// stop a stalled task and hand back what it finished, before it re-queues
// the task (a sensor that cannot stop it, or never heard the request).
const StopGraceSeconds = 300

// MaxProgressEntries bounds the progress entries one heartbeat records.
const MaxProgressEntries = 1000

// OverrunGraceSeconds is how long past twice its task budget a running
// command may go before the platform takes it back: the sensor stops it at
// twice its budget, and its result needs time to arrive.
const OverrunGraceSeconds = 300

// Messages a re-queued command records (command_events, the task's error).
const (
	StalledMessage = "re-queued: nothing moved within the task's stall window (no target finished, no output, no CPU time) and the sensor did not hand back what it finished"
	OverrunMessage = "re-queued: the task ran past twice its time budget and did not report"
	// StoppedEmptyMessage prefixes the error of a stalled task its sensor
	// stopped with nothing finished (re-queued, not failed).
	StoppedEmptyMessage = "re-queued: the task stalled and its sensor stopped it with nothing finished"
)

// ProgressRecorder records the progress a sensor's heartbeat reports for
// the commands it holds. Only commands of tenantID held by sensorID
// (acknowledged or running) are touched; done never decreases and never
// exceeds the command's own target count, whatever the sensor sends.
type ProgressRecorder interface {
	RecordProgress(ctx context.Context, tenantID, sensorID shared.ID, progress map[string]Progress) (int64, error)
}

// StallReaper re-queues running commands that overran their budget, or
// stalled and were not handed back within StopGraceSeconds of the stop
// request (one more dispatch attempt each, like a lost lease).
type StallReaper interface {
	RequeueStalledCommands(ctx context.Context) ([]RequeuedCommand, error)
}

// StallStopper asks the holders of stalled running commands to stop them
// and hand back what they finished: it marks them stop-requested (the
// holder's heartbeat answer lists them as stop_command_ids).
type StallStopper interface {
	RequestStopForStalled(ctx context.Context) ([]RequeuedCommand, error)
}

// StopFinder returns the commands among ids (a heartbeat's running list,
// untrusted) that sensorID holds in tenantID and is asked to stop.
type StopFinder interface {
	CommandsToStop(ctx context.Context, tenantID, sensorID shared.ID, ids []string) ([]string, error)
}

// StopRequeuer re-queues a stop-requested command its holder reports
// failed (it stopped with nothing finished): fenced like FencedUpdate, one
// more dispatch attempt, like a stall. False when the command was not
// stop-requested or the fence does not hold.
type StopRequeuer interface {
	RequeueStopped(ctx context.Context, cmd *Command, expect Fence, message string) (bool, error)
}
