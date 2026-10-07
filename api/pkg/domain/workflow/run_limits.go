package workflow

import (
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Run quotas (research/61 decision A7). An event that matches an automation
// starts one run per subject (a batch of 40 new findings starts 40 runs),
// so the number of runs is bounded here, at creation, not by dropping
// events:
//
//   - MaxRunsPerWorkflowPerHour / MaxRunsPerTenantPerHour: runs created in
//     the last hour. Over it the run is refused as throttled, and one
//     visible "throttled" run per automation per hour records that events
//     were dropped.
//   - MaxActiveRunsPerWorkflow / MaxActiveRunsPerTenant: runs waiting or
//     running. The executor runs a bounded number at a time per tenant and
//     queues the rest; this caps the queue.
const (
	MaxRunsPerWorkflowPerHour = 200
	MaxRunsPerTenantPerHour   = 5000
	MaxActiveRunsPerWorkflow  = 100
	MaxActiveRunsPerTenant    = 500
	RunQuotaWindow            = time.Hour
)

// ThrottledRunPrefix starts the error message of the run that records an
// automation was throttled in the current window.
const ThrottledRunPrefix = "THROTTLED: "

// ErrRunDuplicate: a run of this automation for this event already exists
// (same idempotency key); the event is not run twice.
var ErrRunDuplicate = errors.New("automation run already exists for this event")

// ErrCodeRunThrottled is the domain error code for a run refused by a quota.
const ErrCodeRunThrottled = "AUTOMATION_RUN_THROTTLED"

// NewRunThrottledError is the refusal for a run over a quota.
func NewRunThrottledError(msg string) error {
	return shared.NewDomainError(ErrCodeRunThrottled, msg, shared.ErrValidation)
}

// IsRunThrottled reports whether err is a quota refusal.
func IsRunThrottled(err error) bool {
	var de *shared.DomainError
	return errors.As(err, &de) && de.Code == ErrCodeRunThrottled
}

// SetSubject records the finding or asset the run is about and the key that
// makes the same event start the automation at most once ("" for none).
func (r *Run) SetSubject(subjectID *shared.ID, idempotencyKey string) {
	r.SubjectID = subjectID
	r.IdempotencyKey = idempotencyKey
}
