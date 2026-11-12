package postgres

// Dashboard fact layer writes (docs/architecture/dashboards.md, "Fact layer").
// The facts are computed by database functions of migration
// dashboard_fact_tables; this repository is the entry point the facts
// maintainer and the first-deploy build call.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DashboardNoAssetID is the asset id under which the facts of findings
// without an asset are stored and marked dirty. It never matches an asset,
// an asset group or a viewer's scope.
var DashboardNoAssetID = shared.MustIDFromString("00000000-0000-0000-0000-000000000000")

// DefaultDashboardRebuildBatch is the number of assets one rebuild step
// recomputes in one short transaction.
const DefaultDashboardRebuildBatch = 200

// maxDashboardRebuildBatch bounds one step, so a caller cannot turn the
// batched rebuild into one long transaction.
const maxDashboardRebuildBatch = 2000

// DashboardFactsRepository recomputes the per-asset dashboard facts.
type DashboardFactsRepository struct {
	db *DB
}

// NewDashboardFactsRepository creates a DashboardFactsRepository.
func NewDashboardFactsRepository(db *DB) *DashboardFactsRepository {
	return &DashboardFactsRepository{db: db}
}

// RecomputeAsset recomputes the facts of one asset of the tenant from its
// current findings and returns how many fact rows changed. DashboardNoAssetID
// recomputes the tenant's findings without an asset. Only that tenant's rows
// are read and written.
func (r *DashboardFactsRepository) RecomputeAsset(ctx context.Context, tenantID, assetID shared.ID) (int, error) {
	if tenantID.IsZero() {
		return 0, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT dash_recompute_asset($1, $2)`,
		tenantID.String(), assetID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("recompute dashboard facts: %w", err)
	}
	return n, nil
}

// RebuildTenant recomputes every asset of the tenant in steps of batchSize
// assets (DefaultDashboardRebuildBatch when <= 0). Each step is its own
// transaction, so no lock is held across the rebuild and a live database
// keeps serving writes. The last step recomputes the findings without an
// asset, removes facts of assets that no longer exist and records the
// rebuild time. Idempotent; cancel ctx to stop between steps. Returns the
// number of steps that recomputed assets.
func (r *DashboardFactsRepository) RebuildTenant(ctx context.Context, tenantID shared.ID, batchSize int) (int, error) {
	if tenantID.IsZero() {
		return 0, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	if batchSize <= 0 {
		batchSize = DefaultDashboardRebuildBatch
	}
	batchSize = min(batchSize, maxDashboardRebuildBatch)
	var after sql.NullString
	steps := 0
	for {
		if err := ctx.Err(); err != nil {
			return steps, err
		}
		var last sql.NullString
		if err := r.db.QueryRowContext(ctx, `SELECT dash_rebuild_tenant_batch($1, $2, $3)`,
			tenantID.String(), after, batchSize).Scan(&last); err != nil {
			return steps, fmt.Errorf("rebuild dashboard facts: %w", err)
		}
		if !last.Valid {
			return steps, nil
		}
		steps++
		after = last
	}
}

// MarkAgedAssets marks dirty the assets of the tenant whose open findings
// crossed an age band between since and until, records until as the
// tenant's aged_marked_at, and returns how many assets were marked. A zero
// since means one day before until.
func (r *DashboardFactsRepository) MarkAgedAssets(ctx context.Context, tenantID shared.ID, since, until time.Time) (int, error) {
	if tenantID.IsZero() {
		return 0, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	var sinceArg any
	if !since.IsZero() {
		sinceArg = since
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT dash_mark_aged_assets($1, $2, $3)`,
		tenantID.String(), sinceArg, until).Scan(&n); err != nil {
		return 0, fmt.Errorf("mark aged dashboard assets: %w", err)
	}
	return n, nil
}
