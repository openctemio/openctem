package command

// Sensor refusals of a command (research/25 §3.6, owner decision D8): a
// sensor that refuses a job under its policy reports it; routed scan work
// is re-queued, excluding every sensor that refused it: to another eligible
// sensor at once, or to wait (bounded) for one; it fails after MaxRefusals
// refusals or when the wait ends.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxRefusals is how many sensors may refuse a command before it fails
// (D8: fail after every eligible sensor refused, or after 3 refusals).
const MaxRefusals = 3

// RefusalRecord is one sensor's refusal of a command.
type RefusalRecord struct {
	SensorID string `json:"sensor_id"`
	// SensorName is the sensor's name when it refused (for the reason a
	// person reads; "" when it could not be read).
	SensorName string    `json:"sensor_name,omitempty"`
	Layer      string    `json:"layer"`
	Rule       string    `json:"rule"`
	Detail     string    `json:"detail,omitempty"`
	At         time.Time `json:"at"`
}

// RefusalStore keeps a command's refusals and re-queues it. Implemented by
// the postgres command repository; every method is tenant-scoped.
type RefusalStore interface {
	// CommandRefusals returns the refusals recorded on the command.
	CommandRefusals(ctx context.Context, tenantID, commandID shared.ID) ([]RefusalRecord, error)
	// RequeueRefused puts the command back to pending, unpinned (its zone
	// kept), with rec appended and its sensor excluded from later claims,
	// only if the command is still held under fence. Reports whether it
	// applied. waitUntil, when set, brings the command's expiry forward to
	// it (never later): no sensor can take it now, and it waits at most
	// that long for one.
	RequeueRefused(ctx context.Context, tenantID, commandID shared.ID, fence Fence, rec RefusalRecord, message string, waitUntil *time.Time) (bool, error)
	// AppendRefusal records rec on a command that has failed (best effort,
	// for the record; the command stays failed).
	AppendRefusal(ctx context.Context, tenantID, commandID shared.ID, rec RefusalRecord) error
}
