package postgres

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// EmergingThreats implements dashboard.FactReader with the alert list's own
// summary statement (alertSummary): the tenant first, an alert counted only
// when at least one of its assets is in the read's data scope (nil: the
// whole organization), so each level equals the list filtered to it.
func (r *DashboardWidgetRepository) EmergingThreats(ctx context.Context, scope dashboard.ReadScope) (dashboard.EmergingThreatCounts, error) {
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	c, err := alertSummary(qctx, r.db, scope.TenantID, scope.Assets)
	if err != nil {
		return dashboard.EmergingThreatCounts{}, err
	}
	return dashboard.EmergingThreatCounts{
		Seen: int64(c.Seen), Open: int64(c.Open),
		Immediate: int64(c.Immediate), Digest: int64(c.Digest), Listed: int64(c.Listed),
	}, nil
}
