package command

// Command leases: docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.7
// (owner decision D6), docs/architecture/sensors.md "Command leases".

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Lease lengths. A claim holds DefaultLeaseDuration without renewal. A
// sensor renews it on every heartbeat that lists the command (and on
// start), so a live sensor renews several times per lease: the default is
// above the 90 s after which a silent sensor is marked offline, so a sensor
// whose heartbeats are only late keeps its work.
const (
	DefaultLeaseDuration = 3 * time.Minute
	MinLeaseDuration     = time.Minute
	MaxLeaseDuration     = 30 * time.Minute
)

// ClampLeaseDuration bounds d to [MinLeaseDuration, MaxLeaseDuration];
// zero or negative is DefaultLeaseDuration.
func ClampLeaseDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultLeaseDuration
	}
	return min(max(d, MinLeaseDuration), MaxLeaseDuration)
}

// LeaseExpiredMessage is stored on a command the platform took back from a
// sensor that stopped renewing its lease.
const LeaseExpiredMessage = "re-queued: the sensor holding it stopped renewing its lease"

// RequeuedCommand is a command taken back from a sensor whose lease ran out.
type RequeuedCommand struct {
	ID       shared.ID
	TenantID shared.ID
	// SensorID is the sensor that held it; Epoch the lease epoch it held.
	SensorID *shared.ID
	Epoch    int
}

// ReleasedCommand is a command taken back from a sensor that was revoked or
// disabled while it held it (RFC-040 §5.2, "revocation reaches running work").
type ReleasedCommand struct {
	ID   shared.ID
	Type CommandType
	// PrevStatus is the state the sensor held it in (acknowledged or
	// running); Epoch the lease epoch it held.
	PrevStatus CommandStatus
	Epoch      int
	// Requeued is true when the command went back to the queue for another
	// sensor, false when it was failed because it was addressed to that
	// sensor only.
	Requeued bool
}

// HolderReleaser takes back, at once, every command a sensor holds under a
// lease, when the sensor stops being trusted (revoked or disabled):
// routed scan work is re-queued for another sensor, anything addressed to
// that sensor only is failed with failMessage. Either way the old holder no
// longer holds it, so its late start, complete or fail is refused by the
// fence (FencedUpdate).
type HolderReleaser interface {
	ReleaseHeldBySensor(ctx context.Context, tenantID, sensorID shared.ID, requeueMessage, failMessage string) ([]ReleasedCommand, error)
}

// Messages stored on commands taken back from a revoked or disabled sensor.
const (
	SensorRevokedRequeuedMessage  = "re-queued: the sensor holding it was revoked"
	SensorRevokedFailedMessage    = "failed: the sensor it was addressed to was revoked while holding it"
	SensorDisabledRequeuedMessage = "re-queued: the sensor holding it was disabled"
	SensorDisabledFailedMessage   = "failed: the sensor it was addressed to was disabled while holding it"
)

// Fence is what a sensor-side state change expects to still be true: the
// command is held by SensorID, in Status, under lease epoch Epoch.
type Fence struct {
	SensorID string
	Status   CommandStatus
	Epoch    int
}

// LeaseRenewer extends the leases of the commands a sensor holds.
type LeaseRenewer interface {
	// RenewLeases renews the commands in ids that sensorID holds, or all it
	// holds when all is set.
	RenewLeases(ctx context.Context, tenantID, sensorID shared.ID, ids []string, all bool) (int64, error)
}

// CancelFinder finds, among the commands a sensor says it holds (its
// heartbeat's running list), the ones it must stop: canceled, closed by the
// platform (a scan run timeout fails them), re-queued after its lease ran
// out, held by another sensor, or unknown. A command the sensor still holds,
// or completed itself, is never returned. The heartbeat answers them as
// cancel_command_ids, which the SDK's poller stops and releases.
type CancelFinder interface {
	CommandsToCancel(ctx context.Context, tenantID, sensorID shared.ID, ids []string) ([]string, error)
}

// OpenCanceler cancels a command only while it is still open (pending,
// acknowledged or running): one that finished in the meantime is left as
// it is and false is returned.
type OpenCanceler interface {
	CancelIfOpen(ctx context.Context, cmd *Command) (bool, error)
}

// LeaseReaper takes back the commands whose lease ran out.
type LeaseReaper interface {
	RequeueExpiredLeases(ctx context.Context) ([]RequeuedCommand, error)
}

// FencedUpdater applies a sensor-side state change only under the fence.
type FencedUpdater interface {
	FencedUpdate(ctx context.Context, cmd *Command, expect Fence) (bool, error)
}
