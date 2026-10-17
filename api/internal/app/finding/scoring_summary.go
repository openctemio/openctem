package finding

// One notification per scoring change instead of one per finding
// (docs/architecture/scoring-versions.md, "No alert storms").

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type coalesceKey struct{}

// WithCoalescedChangeEvents marks a recompute caused by a scoring change: a
// class change is still classified and audited, but no per-finding
// priority_changed event is published (the change's summary covers it),
// except for a move into P0.
func WithCoalescedChangeEvents(ctx context.Context) context.Context {
	return context.WithValue(ctx, coalesceKey{}, true)
}

func changeEventsCoalesced(ctx context.Context) bool {
	v, _ := ctx.Value(coalesceKey{}).(bool)
	return v
}

// TxOutboxEnqueuer writes a notification outbox row inside a transaction.
type TxOutboxEnqueuer interface {
	EnqueueInTx(ctx context.Context, tx *sql.Tx, params outbox.EnqueueParams) error
}

// OutboxScoringSummaryPublisher sends a scoring change's summary through the
// notification outbox.
type OutboxScoringSummaryPublisher struct {
	outbox TxOutboxEnqueuer
	logger *logger.Logger
}

// NewOutboxScoringSummaryPublisher wires the outbox.
func NewOutboxScoringSummaryPublisher(o TxOutboxEnqueuer, log *logger.Logger) *OutboxScoringSummaryPublisher {
	if log == nil {
		log = logger.NewNop()
	}
	return &OutboxScoringSummaryPublisher{outbox: o, logger: log.With("service", "scoring-summary")}
}

// scoringSourceLabel names what changed, for the notification text (the
// server renders it outside the web app, so it is English).
func scoringSourceLabel(source string) string {
	switch source {
	case "platform_model":
		return "a new scoring model"
	case "risk_settings":
		return "risk scoring settings"
	case "priority_rules":
		return "priority rules"
	case "sla_policy":
		return "SLA policy"
	default:
		return "scoring"
	}
}

// PublishScoringSummaryInTx enqueues one summary inside tx, the transaction
// that marks it notified (so a failed enqueue leaves it pending). A change
// that moved nothing sends nothing.
func (p *OutboxScoringSummaryPublisher) PublishScoringSummaryInTx(ctx context.Context, tx *sql.Tx, s scoring.ChangeSummary) error {
	if p == nil || p.outbox == nil || (s.Changed == 0 && s.DeadlinesTightened == 0) {
		return nil
	}
	// Severity follows the most urgent movement, so the channel's severity
	// filter (critical and high by default) still lets an escalation or a
	// tightened deadline through.
	severity := "low"
	switch {
	case s.RaisedToP0 > 0:
		severity = "critical"
	case s.Raised > 0, s.DeadlinesTightened > 0:
		severity = "high"
	}
	body := fmt.Sprintf("%d of %d open findings changed priority: %d moved up (%d to P0), %d moved down. %d SLA deadlines moved earlier. Closed findings and past reports are unchanged.",
		s.Changed, s.Checked, s.Raised, s.RaisedToP0, s.Lowered, s.DeadlinesTightened)
	params := outbox.EnqueueParams{
		TenantID:      s.TenantID,
		EventType:     string(integration.EventTypeScoringChangeApplied),
		AggregateType: "scoring_change",
		Title:         fmt.Sprintf("Scoring changed (%s): %d findings changed priority", scoringSourceLabel(s.Source), s.Changed),
		Body:          body,
		Severity:      severity,
		URL:           "/findings?sort=-priority",
		Metadata: map[string]any{
			"scoring_change_id":   s.ChangeID,
			"source":              s.Source,
			"summary":             s.Summary,
			"findings_checked":    s.Checked,
			"findings_changed":    s.Changed,
			"findings_raised":     s.Raised,
			"raised_to_p0":        s.RaisedToP0,
			"findings_lowered":    s.Lowered,
			"deadlines_tightened": s.DeadlinesTightened,
		},
	}
	if err := p.outbox.EnqueueInTx(ctx, tx, params); err != nil {
		return fmt.Errorf("enqueue scoring change summary: %w", err)
	}
	p.logger.Info("scoring change summary enqueued", "tenant_id", s.TenantID.String(),
		"scoring_change_id", s.ChangeID, "changed", s.Changed)
	return nil
}
