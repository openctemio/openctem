package postgres

// Command change notification for the sensor control stream
// (docs/rfcs/RFC-059-sensor-transport-v3.md §6): after a write that can give
// a sensor new work (a command becomes pending) or take work away (a held
// command is cancelled), the repository tells the notifier, which wakes the
// control streams of that tenant or sensor. The database stays the only
// source of truth: a wake carries no data, a lost one costs latency only.

import (
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CommandChangeNotifier hears that commands changed. Implementations must
// not block.
type CommandChangeNotifier interface {
	// Wake wakes the streams of tenantID; only sensorID's when it is not "".
	Wake(tenantID, sensorID string)
	// WakeAll wakes every stream (a bulk change whose tenants are unknown).
	WakeAll()
}

// SetChangeNotifier wires the notifier (nil: none).
func (r *CommandRepository) SetChangeNotifier(n CommandChangeNotifier) { r.notify = n }

// changed notifies about one command after a successful write: pending
// work wakes the sensor it is pinned to, else the tenant; a cancelled
// command wakes the sensor that holds it. Other states need no push.
func (r *CommandRepository) changed(cmd *command.Command) {
	if r.notify == nil || cmd == nil {
		return
	}
	switch cmd.Status {
	case command.CommandStatusPending:
		r.notify.Wake(cmd.TenantID.String(), idOrEmpty(cmd.SensorID))
	case command.CommandStatusCanceled:
		if cmd.SensorID != nil {
			r.notify.Wake(cmd.TenantID.String(), cmd.SensorID.String())
		}
	}
}

// changedTenant wakes the tenant's streams (work went back to the pool).
func (r *CommandRepository) changedTenant(tenantID shared.ID) {
	if r.notify != nil {
		r.notify.Wake(tenantID.String(), "")
	}
}

// changedSensor wakes one sensor's streams.
func (r *CommandRepository) changedSensor(tenantID shared.ID, sensorID string) {
	if r.notify != nil {
		r.notify.Wake(tenantID.String(), sensorID)
	}
}

// changedMany wakes every stream after a bulk change of n commands.
func (r *CommandRepository) changedMany(n int64) {
	if r.notify != nil && n > 0 {
		r.notify.WakeAll()
	}
}

func idOrEmpty(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
