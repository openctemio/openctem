package exposurebridge

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ProjectTemplateMatches files the info-severity matches of a template
// scanner as info exposures of their assets (exposure.NewTemplateMatchEvent),
// with the same dedupe and reactivate rules as every projection: a match
// seen again bumps its event's last_seen, a resolved one is reactivated, a
// false positive stays closed. It returns how many matches were recorded.
// Best-effort per match: one bad match is logged and skipped.
func (b *Bridge) ProjectTemplateMatches(ctx context.Context, tenantID shared.ID, matches []exposure.TemplateMatch) (int, error) {
	n := 0
	for _, m := range matches {
		if m.AssetID.IsZero() {
			continue
		}
		ev, err := exposure.NewTemplateMatchEvent(tenantID, m)
		if err != nil {
			b.logger.Warn("template match not filed as an exposure",
				"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
			continue
		}
		if err := upsertExposureEvent(ctx, b.exposureRepo, b.historyRepo, b.logger, ev, "template scan"); err != nil {
			b.logger.Warn("template match exposure not stored",
				"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
			continue
		}
		n++
	}
	return n, nil
}
