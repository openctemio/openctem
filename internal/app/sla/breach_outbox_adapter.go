// B4 wire (Q1/WS-E): SLA breach events → notification outbox. Lives
// alongside sla.Service/Applier so a single `sla` package owns both
// deadline computation and breach fan-out. Previously a separate
// `slabreach` subpackage to dodge an (outdated) import-cycle concern.
//
// The adapter uses the NotificationEnqueuer interface so it can be
// unit-tested without the full outbox graph. *outbox.Service
// satisfies the interface at runtime (structural typing).

package sla

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/api/internal/app/outbox"
	"github.com/openctemio/api/internal/infra/controller"
)

// NotificationEnqueuer is the narrow surface the BreachOutboxAdapter
// needs. *outbox.Service satisfies it directly.
type NotificationEnqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// BreachOutboxAdapter satisfies controller.SLABreachPublisher by
// translating each breach event into an outbox notification. Wire via
// SLAEscalationController.SetBreachPublisher(adapter).
type BreachOutboxAdapter struct {
	outbox NotificationEnqueuer
}

// NewBreachOutboxAdapter wires the enqueuer into the adapter.
func NewBreachOutboxAdapter(outbox NotificationEnqueuer) *BreachOutboxAdapter {
	return &BreachOutboxAdapter{outbox: outbox}
}

// Publish enqueues a single breach notification. Implements
// controller.SLABreachPublisher.
//
// Severity is fixed at "high" — SLA breach is always notable; channels
// can still filter it out via their integration config.
func (a *BreachOutboxAdapter) Publish(ctx context.Context, event controller.SLABreachEvent) error {
	if a == nil || a.outbox == nil {
		return nil // misconfigured → silent no-op, escalation is advisory
	}

	fidUUID, err := uuid.Parse(event.FindingID.String())
	if err != nil {
		return fmt.Errorf("parse finding id: %w", err)
	}

	overdue := event.OverdueDuration.Round(time.Minute)
	params := outbox.EnqueueParams{
		TenantID:      event.TenantID,
		EventType:     "sla_breach",
		AggregateType: "finding",
		AggregateID:   &fidUUID,
		Title:         fmt.Sprintf("SLA breached: finding %s (overdue %s)", event.FindingID.String(), overdue),
		Body: fmt.Sprintf(
			"Finding %s missed its SLA deadline (%s) by %s. The escalation controller marked it breached at %s.",
			event.FindingID.String(),
			event.SLADeadline.UTC().Format(time.RFC3339),
			overdue,
			event.At.UTC().Format(time.RFC3339),
		),
		Severity: "high",
		Metadata: map[string]any{
			"finding_id":         event.FindingID.String(),
			"sla_deadline":       event.SLADeadline.UTC().Format(time.RFC3339),
			"overdue_duration":   event.OverdueDuration.String(),
			"overdue_seconds":    int64(event.OverdueDuration.Seconds()),
			"breached_at":        event.At.UTC().Format(time.RFC3339),
			"escalation_source":  "sla_escalation_controller",
		},
	}

	if err := a.outbox.Enqueue(ctx, params); err != nil {
		return fmt.Errorf("enqueue sla breach notification: %w", err)
	}
	return nil
}
