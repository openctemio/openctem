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

// LeaseReaper takes back the commands whose lease ran out.
type LeaseReaper interface {
	RequeueExpiredLeases(ctx context.Context) ([]RequeuedCommand, error)
}

// FencedUpdater applies a sensor-side state change only under the fence.
type FencedUpdater interface {
	FencedUpdate(ctx context.Context, cmd *Command, expect Fence) (bool, error)
}
