package postgres

// A web service whose page changed is captured again
// (docs/rfcs/RFC-081-web-evidence-screenshots.md, docs/architecture/asset-coverage.md).

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// pageRecaptureGap is the least time between two on-change captures of one
// asset (a page that flaps does not storm the sensor).
const pageRecaptureGap = "24 hours"

// PagesChanged moves the screenshot pair of each listed web service of the
// tenant to due now, unless the pair was attempted in the last 24 hours. Only
// a pair that exists and is waiting for its cadence (covered) or already due
// moves: a pair that is paused (screenshots off), not applicable, queued or
// blocked keeps its state. Every row is matched on tenant_id.
func (r *AssetCoverageRepository) PagesChanged(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}
	if _, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage
		SET next_due_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND capability = 'capture.screenshot'
		  AND state IN ('covered', 'due') AND next_due_at > now()
		  AND (last_attempt_at IS NULL OR last_attempt_at < now() - interval '`+pageRecaptureGap+`')`,
		tenantID.String(), pq.Array(ids)); err != nil {
		return fmt.Errorf("move changed pages' screenshot pairs to due: %w", err)
	}
	return nil
}
