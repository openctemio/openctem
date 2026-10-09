package automation

import (
	"context"
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

// ErrRunCooldown: the automation already ran for this subject and trigger
// within the cooldown (the loop guard); the event does not start it again.
var ErrRunCooldown = errors.New("automation already ran for this subject within the cooldown")

// RecentSubjectRunChecker answers the subject cooldown. Optional extension
// of RunRepository.
type RecentSubjectRunChecker interface {
	// HasRecentSubjectRun reports whether workflowID (in tenantID) has a run
	// for subjectID and triggerType created after since.
	HasRecentSubjectRun(ctx context.Context, tenantID, workflowID, subjectID shared.ID, triggerType TriggerType, since time.Time) (bool, error)
}

// RunOutcomeReader reads the latest outcomes of a workflow's runs. Optional
// extension of RunRepository, used to pause an automation that keeps failing.
type RunOutcomeReader interface {
	// LatestOutcomes returns the statuses of the workflow's latest n finished
	// runs (completed or failed, newest first), leaving out the records of
	// throttled events.
	LatestOutcomes(ctx context.Context, tenantID, workflowID shared.ID, n int) ([]RunStatus, error)
}

// StaleRunReaper ends runs nothing will finish. Optional extension of
// RunRepository.
type StaleRunReaper interface {
	// FailStaleRuns fails the pending and running runs created before
	// before (across tenants: a maintenance job), with their open steps,
	// and returns how many runs it ended.
	FailStaleRuns(ctx context.Context, before time.Time, reason string) (int64, error)
}
