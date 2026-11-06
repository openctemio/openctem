package automation

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Run trace and deliveries (RFC-125 §5).
//
// Every step records how many subjects reached it (in), how many it acted on
// or would act on (out) and, per reason, how many it left alone. Every step
// that leaves the platform (a notification, a ticket) records a delivery: what
// it sent in a live run, or would have sent in a simulate run, with a payload
// cut down to an allow-list of fields.

// Retention of runs (with their steps and deliveries).
const (
	SimulateRunRetention = 30 * 24 * time.Hour
	LiveRunRetention     = 180 * 24 * time.Hour
)

// RetainedUntil is when a run created at createdAt in mode is deleted.
func RetainedUntil(mode Mode, createdAt time.Time) time.Time {
	if mode == ModeSimulate {
		return createdAt.Add(SimulateRunRetention)
	}
	return createdAt.Add(LiveRunRetention)
}

// Skip reasons a step records.
const (
	SkipConditionFalse   = "condition_false"
	SkipBranchNotTaken   = "branch_not_taken"
	SkipNoChange         = "no_change"
	SkipNoSubject        = "no_subject"
	SkipNotAuthorized    = "refused:not_authorized"
	SkipStatusNotAllowed = "refused:status_not_allowed"
)

// DeliveryStatus is the state of a delivery.
type DeliveryStatus string

// Delivery statuses.
const (
	// DeliverySimulated: a simulate run's delivery; never sent.
	DeliverySimulated DeliveryStatus = "simulated"
	DeliverySent      DeliveryStatus = "sent"
	DeliveryFailed    DeliveryStatus = "failed"
	// DeliveryHeld: the integration's create policy held it back.
	DeliveryHeld DeliveryStatus = "held"
)

// Delivery is one message or ticket a step sent or would have sent.
type Delivery struct {
	ID       shared.ID
	TenantID shared.ID
	RunID    shared.ID
	NodeKey  string
	// Channel: slack, teams, email, webhook, jira, github.
	Channel string
	// Target: the integration id, project or repository it goes to.
	Target string
	Mode   Mode
	Status DeliveryStatus
	// Attempts made (0 for a simulated delivery).
	Attempts int
	// IdempotencyKey is unique per tenant ("<run id>:<node key>").
	IdempotencyKey string
	// Payload holds only allow-listed fields (DeliveryPayload).
	Payload     map[string]any
	ExternalRef string
	Error       string
	CreatedAt   time.Time
}

// deliveryPayloadFields is the allow-list of payload fields a delivery keeps.
// Bodies, headers, URLs with query strings and any secret never are.
var deliveryPayloadFields = map[string]int{
	"title":       200,
	"severity":    20,
	"subject_id":  64,
	"finding_id":  64,
	"provider":    20,
	"project_key": 64,
	"issue_type":  64,
	"repository":  200,
	"would":       64,
	"body_chars":  0,
	"held_reason": 200,
}

// DeliveryPayload keeps the allow-listed fields of p, strings cut to their
// limit. Unknown fields are dropped.
func DeliveryPayload(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		limit, ok := deliveryPayloadFields[k]
		if !ok {
			continue
		}
		if s, isStr := v.(string); isStr {
			if limit > 0 && len(s) > limit {
				s = s[:limit]
			}
			out[k] = s
			continue
		}
		switch v.(type) {
		case int, int64, float64, bool:
			out[k] = v
		}
	}
	return out
}

// DeliveryRepository stores deliveries. Every method is tenant-scoped.
type DeliveryRepository interface {
	// Record stores d; a second delivery with the same idempotency key is
	// ignored.
	Record(ctx context.Context, d *Delivery) error
	ListByRun(ctx context.Context, tenantID, runID shared.ID) ([]*Delivery, error)
}

// StepTrace is what a step records about the subjects that reached it.
type StepTrace struct {
	In      int
	Out     int
	Skipped map[string]int
}

// Skip adds n subjects left alone for reason.
func (t *StepTrace) Skip(reason string, n int) {
	if t.Skipped == nil {
		t.Skipped = map[string]int{}
	}
	t.Skipped[reason] += n
}
