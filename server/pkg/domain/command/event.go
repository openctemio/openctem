package command

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Event is one change in a command's life (command_events, written by a
// trigger on commands): queued, claimed, started, refused, requeued,
// completed, failed, canceled, expired.
type Event struct {
	ID        shared.ID
	CommandID shared.ID
	Event     string
	Status    string
	Attempt   int
	// Platform: the command was a platform job. Its sensor is never named
	// to the tenant and its message is masked (sensor.RedactPlatformText).
	Platform  bool
	SensorID  *shared.ID
	Code      string
	Message   string
	CreatedAt time.Time
}

// MaxRunEvents caps the events one run timeline read returns.
const MaxRunEvents = 2000

// EventReader reads command events.
type EventReader interface {
	// ListForRun returns the events of runID's commands in tenantID, oldest
	// first, at most limit; truncated reports that more exist.
	ListForRun(ctx context.Context, tenantID, runID shared.ID, limit int) (events []Event, truncated bool, err error)
}
