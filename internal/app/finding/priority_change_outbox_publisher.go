package finding

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/openctemio/api/internal/app/outbox"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// OutboxEnqueuer is the slice of outbox.Service this publisher needs.
// Declared here (consumer side) so tests can substitute a fake without
// standing up the whole notification stack.
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// OutboxPriorityChangePublisher is the production PriorityChangePublisher:
// it turns a priority ESCALATION into a notification-outbox entry, which the
// outbox scheduler then fans out to the tenant's connected Slack/Teams/
// Telegram/email/webhook integrations.
//
// Why escalations only. PriorityChangeEvent is deliberately broader than what
// is worth paging a human about — it also fires on first classification
// (PreviousClass == nil) and on de-escalations:
//
//   - First classification fires once per newly-ingested finding. Those are
//     already announced by the "new_finding" notification, so publishing them
//     here would double-notify every finding of every ingest batch.
//   - A de-escalation (P0 -> P2, e.g. a compensating control was applied) is
//     good news and does not need to interrupt anyone.
//
// The escalation is the case the operator cannot afford to miss: a finding
// they already triaged as low-urgency silently became P0 because its CVE was
// added to KEV or its asset landed on a validated attack path.
//
// Delivery severity is derived from the NEW class (P0 -> critical ... P3 ->
// low) so the tenant's existing per-integration severity filter keeps working
// without a new knob: an integration set to "critical only" receives P0
// escalations and nothing else.
type OutboxPriorityChangePublisher struct {
	outbox OutboxEnqueuer
	logger *logger.Logger
}

// NewOutboxPriorityChangePublisher wires the publisher to the notification
// outbox. A nil enqueuer yields a publisher whose Publish is a no-op, so the
// composition root can wire it unconditionally.
func NewOutboxPriorityChangePublisher(o OutboxEnqueuer, log *logger.Logger) *OutboxPriorityChangePublisher {
	if log == nil {
		log = logger.NewNop()
	}
	return &OutboxPriorityChangePublisher{
		outbox: o,
		logger: log.With("service", "priority-change-outbox"),
	}
}

// Publish implements PriorityChangePublisher.
func (p *OutboxPriorityChangePublisher) Publish(ctx context.Context, ev PriorityChangeEvent) error {
	if p == nil || p.outbox == nil {
		return nil
	}
	if !isEscalation(ev.PreviousClass, ev.NewClass) {
		return nil
	}

	previous := string(*ev.PreviousClass)
	metadata := map[string]any{
		"previous_class": previous,
		"new_class":      string(ev.NewClass),
		"reason":         ev.Reason,
		"source":         ev.Source,
		"changed_at":     ev.At,
	}
	if ev.RuleID != nil {
		metadata["rule_id"] = ev.RuleID.String()
	}

	params := outbox.EnqueueParams{
		TenantID:      ev.TenantID,
		EventType:     string(integration.EventTypeFindingPriorityEscalated),
		AggregateType: "finding",
		Title:         fmt.Sprintf("Priority escalated %s -> %s", previous, ev.NewClass),
		Body:          ev.Reason,
		Severity:      priorityToOutboxSeverity(ev.NewClass),
		URL:           fmt.Sprintf("/findings/%s", ev.FindingID.String()),
		Metadata:      metadata,
	}
	// AggregateID is a *uuid.UUID; shared.ID is uuid-backed, but stay
	// fail-safe — an unparseable ID must not drop the whole notification.
	if findingUUID, err := uuid.Parse(ev.FindingID.String()); err == nil {
		params.AggregateID = &findingUUID
	}

	if err := p.outbox.Enqueue(ctx, params); err != nil {
		return fmt.Errorf("enqueue priority escalation notification: %w", err)
	}
	p.logger.Info("priority escalation notification enqueued",
		"tenant_id", ev.TenantID.String(),
		"finding_id", ev.FindingID.String(),
		"previous_class", previous,
		"new_class", string(ev.NewClass),
		"source", ev.Source,
	)
	return nil
}

// priorityRank orders classes by urgency: lower is more urgent. Unknown
// classes sort last so they can never look like an escalation.
func priorityRank(c vulnerability.PriorityClass) int {
	switch c {
	case vulnerability.PriorityP0:
		return 0
	case vulnerability.PriorityP1:
		return 1
	case vulnerability.PriorityP2:
		return 2
	case vulnerability.PriorityP3:
		return 3
	default:
		return 99
	}
}

// isEscalation reports whether the finding moved UP in urgency. First
// classification (previous == nil) is not an escalation — see the type doc.
func isEscalation(previous *vulnerability.PriorityClass, next vulnerability.PriorityClass) bool {
	if previous == nil {
		return false
	}
	if priorityRank(next) == 99 {
		return false
	}
	return priorityRank(next) < priorityRank(*previous)
}

// priorityToOutboxSeverity maps a priority class onto the outbox severity
// scale so the tenant's existing per-integration severity filter applies.
func priorityToOutboxSeverity(c vulnerability.PriorityClass) string {
	switch c {
	case vulnerability.PriorityP0:
		return "critical"
	case vulnerability.PriorityP1:
		return "high"
	case vulnerability.PriorityP2:
		return "medium"
	default:
		return "low"
	}
}
