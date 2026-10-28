package aianalysis

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// OutboxDowngradeNotifier sends the downgrade notice through the
// notification outbox (the organization's configured channels).
type OutboxDowngradeNotifier struct {
	Outbox *outbox.Service
	Logger *logger.Logger
}

// NotifyAIDowngrade implements DowngradeNotifier.
func (n OutboxDowngradeNotifier) NotifyAIDowngrade(ctx context.Context, tenantID shared.ID, u aidom.UseCase, d aidom.Decisions) {
	if n.Outbox == nil {
		return
	}
	err := n.Outbox.Enqueue(ctx, outbox.EnqueueParams{
		TenantID:      tenantID,
		EventType:     "ai_use_case_downgraded",
		AggregateType: "ai_use_case",
		Title:         "AI auto-apply turned back to suggest",
		Body: fmt.Sprintf("People overrode %d of the last %d AI %s suggestions, so auto-apply now waits for a person. An administrator can turn it on again in Settings > AI.",
			d.Overrides, d.Total, u),
		Severity: "medium",
		URL:      "/settings/ai",
		Metadata: map[string]any{"use_case": string(u), "overrides": d.Overrides, "decisions": d.Total},
	})
	if err != nil && n.Logger != nil {
		n.Logger.Warn("failed to enqueue the AI downgrade notice", "error", err)
	}
}
