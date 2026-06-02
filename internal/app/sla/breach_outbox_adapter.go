// B4 wire: SLA breach events → notification outbox. Lives
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
	"database/sql"
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
	EnqueueInTx(ctx context.Context, tx *sql.Tx, params outbox.EnqueueParams) error
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
	params, err := buildBreachParams(event)
	if err != nil {
		return err
	}
	if err := a.outbox.Enqueue(ctx, params); err != nil {
		return fmt.Errorf("enqueue sla breach notification: %w", err)
	}
	return nil
}

// PublishTx enqueues the breach notification inside the caller's transaction,
// so the finding's `breached` transition and this notification commit together.
// Implements controller.SLABreachTxPublisher.
func (a *BreachOutboxAdapter) PublishTx(ctx context.Context, tx *sql.Tx, event controller.SLABreachEvent) error {
	if a == nil || a.outbox == nil {
		return nil
	}
	params, err := buildBreachParams(event)
	if err != nil {
		return err
	}
	if err := a.outbox.EnqueueInTx(ctx, tx, params); err != nil {
		return fmt.Errorf("enqueue sla breach notification in tx: %w", err)
	}
	return nil
}

// buildBreachParams translates a breach event into outbox enqueue params.
func buildBreachParams(event controller.SLABreachEvent) (outbox.EnqueueParams, error) {
	fidUUID, err := uuid.Parse(event.FindingID.String())
	if err != nil {
		return outbox.EnqueueParams{}, fmt.Errorf("parse finding id: %w", err)
	}

	overdue := event.OverdueDuration.Round(time.Minute)
	return outbox.EnqueueParams{
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
			"finding_id":        event.FindingID.String(),
			"sla_deadline":      event.SLADeadline.UTC().Format(time.RFC3339),
			"overdue_duration":  event.OverdueDuration.String(),
			"overdue_seconds":   int64(event.OverdueDuration.Seconds()),
			"breached_at":       event.At.UTC().Format(time.RFC3339),
			"escalation_source": "sla_escalation_controller",
		},
	}, nil
}
