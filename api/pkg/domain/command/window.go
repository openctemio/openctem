package command

// Scan windows at dispatch (docs/architecture/scan-windows.md): what the
// claim and the closing-window controller write on commands.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WindowDeferral is how a job waits for its scan window.
type WindowDeferral struct {
	// Until is when the job is due again (scheduled_at).
	Until time.Time
	// Hold is the explanation stored in window_hold.
	Hold json.RawMessage
	// ExtendExpiry moves expires_at by the wait, so waiting where the
	// organization said to wait never counts against the job's time to live.
	ExtendExpiry bool
	// RunOpensAt, when set, moves the run's deadline to this instant plus
	// the run's timeout (never earlier than it is).
	RunOpensAt *time.Time
}

// WindowHoldStore writes the claim's window decisions. Every write applies
// only while the command is still pending with the payload that was read.
type WindowHoldStore interface {
	// DeferPending defers a pending command.
	DeferPending(ctx context.Context, cmd *Command, d WindowDeferral) (bool, error)
	// SplitPending keeps keep in the command and creates a sibling of the
	// same step with wait, deferred by d, in one transaction. It returns the
	// sibling's id.
	SplitPending(ctx context.Context, cmd *Command, keep, wait json.RawMessage, d WindowDeferral) (shared.ID, bool, error)
	// RecordWindowPolicies stores the allow policies a pending command is
	// about to run under (for concurrency caps).
	RecordWindowPolicies(ctx context.Context, cmd *Command, policyIDs []string) (bool, error)
	// CountRunningUnderPolicies counts the tenant's acknowledged and running
	// commands under each of policyIDs.
	CountRunningUnderPolicies(ctx context.Context, tenantID shared.ID, policyIDs []string) (map[string]int, error)
	// ReleaseWindowHolds makes every deferred command of the tenant due now,
	// so the next claim evaluates it again (a policy or override changed).
	ReleaseWindowHolds(ctx context.Context, tenantID shared.ID) (int64, error)
}

// WindowClosingStore is what the closing-window controller reads and
// writes.
type WindowClosingStore interface {
	// RunningProbing lists the tenant's acknowledged and running probing
	// commands (scan, validate, retest, connector scan), at most limit.
	RunningProbing(ctx context.Context, tenantID shared.ID, limit int) ([]*RunningCommand, error)
	// MarkWindowClosed records when a running command was first seen
	// outside its windows (only when not recorded yet).
	MarkWindowClosed(ctx context.Context, tenantID shared.ID, ids []shared.ID, at time.Time) error
	// ClearWindowClosed forgets that mark for commands back inside their
	// windows.
	ClearWindowClosed(ctx context.Context, tenantID shared.ID, ids []shared.ID) error
	// RequeueForWindow returns a running command to pending, unpinned,
	// deferred by d, while it is still held by the sensor under the epoch
	// that was read. It does not count a dispatch attempt.
	RequeueForWindow(ctx context.Context, rc *RunningCommand, d WindowDeferral) (bool, error)
}

// RunningCommand is a running command as the closing-window controller sees
// it.
type RunningCommand struct {
	Command        *Command
	SensorID       *shared.ID
	LeaseEpoch     int
	WindowClosedAt *time.Time
}

// WindowClosedMessage is recorded on a job the closing-window controller
// returned to the queue.
const WindowClosedMessage = "SCAN_WINDOW_CLOSED: the scan window closed while this job ran; it runs again at the next opening"
