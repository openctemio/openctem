package postgres

// Asset risk rescore queue (docs/architecture/asset-risk-score.md). Rows are
// written by database triggers (migration asset_risk_queue) and claimed by
// the asset-risk-score worker.

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetRiskQueueRepository implements asset.RiskQueueRepository.
type AssetRiskQueueRepository struct {
	db *DB
}

// NewAssetRiskQueueRepository creates the repository.
func NewAssetRiskQueueRepository(db *DB) *AssetRiskQueueRepository {
	return &AssetRiskQueueRepository{db: db}
}

var _ asset.RiskQueueRepository = (*AssetRiskQueueRepository)(nil)

// ClaimForPlatform removes up to limit due rows, oldest first. SKIP LOCKED
// keeps two replicas from claiming the same asset.
func (r *AssetRiskQueueRepository) ClaimForPlatform(ctx context.Context, limit int) ([]asset.RiskQueueItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	const q = `
		DELETE FROM asset_risk_queue q
		USING (
			SELECT asset_id FROM asset_risk_queue
			WHERE enqueued_at <= now()
			ORDER BY enqueued_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		) due
		WHERE q.asset_id = due.asset_id
		RETURNING q.tenant_id, q.asset_id`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("claim asset risk queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]asset.RiskQueueItem, 0, limit)
	for rows.Next() {
		var tid, aid string
		if err := rows.Scan(&tid, &aid); err != nil {
			return nil, fmt.Errorf("scan asset risk queue: %w", err)
		}
		tenantID, err := shared.IDFromString(tid)
		if err != nil {
			continue
		}
		assetID, err := shared.IDFromString(aid)
		if err != nil {
			continue
		}
		items = append(items, asset.RiskQueueItem{TenantID: tenantID, AssetID: assetID})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset risk queue: %w", err)
	}
	return items, nil
}

// Enqueue queues the given assets of the tenant. The join on assets keeps a
// foreign asset id out of the queue.
func (r *AssetRiskQueueRepository) Enqueue(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	const q = `
		INSERT INTO asset_risk_queue (asset_id, tenant_id)
		SELECT a.id, a.tenant_id FROM assets a
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL
		ORDER BY a.id
		ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
			WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at`
	if _, err := r.db.ExecContext(ctx, q, tenantID.String(), pq.Array(ids)); err != nil {
		return fmt.Errorf("enqueue asset risk rescore: %w", err)
	}
	return nil
}

// EnqueueTenant queues every live asset of the tenant.
func (r *AssetRiskQueueRepository) EnqueueTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	const q = `
		INSERT INTO asset_risk_queue (asset_id, tenant_id)
		SELECT a.id, a.tenant_id FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		ORDER BY a.id
		ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
			WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at`
	res, err := r.db.ExecContext(ctx, q, tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("enqueue tenant risk rescore: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EnqueueAllForPlatform queues every live asset with a later due time. An
// asset already queued keeps its row (DO NOTHING), so a real change is never
// pushed back.
func (r *AssetRiskQueueRepository) EnqueueAllForPlatform(ctx context.Context, delay time.Duration) (int64, error) {
	if delay < 0 {
		delay = 0
	}
	const q = `
		INSERT INTO asset_risk_queue (asset_id, tenant_id, enqueued_at)
		SELECT a.id, a.tenant_id, now() + make_interval(secs => $1)
		FROM assets a
		WHERE a.deleted_at IS NULL AND a.tenant_id IS NOT NULL
		ON CONFLICT (asset_id) DO NOTHING`
	res, err := r.db.ExecContext(ctx, q, delay.Seconds())
	if err != nil {
		return 0, fmt.Errorf("enqueue risk reconcile: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// StatsForPlatform returns the queue depth and the age of the oldest due row.
func (r *AssetRiskQueueRepository) StatsForPlatform(ctx context.Context) (asset.RiskQueueStats, error) {
	const q = `
		SELECT COUNT(*),
		       COALESCE(EXTRACT(EPOCH FROM now() - MIN(enqueued_at) FILTER (WHERE enqueued_at <= now())), 0)
		FROM asset_risk_queue`
	var (
		depth  int64
		oldest float64
	)
	if err := r.db.QueryRowContext(ctx, q).Scan(&depth, &oldest); err != nil {
		return asset.RiskQueueStats{}, fmt.Errorf("asset risk queue stats: %w", err)
	}
	return asset.RiskQueueStats{Depth: depth, OldestAge: time.Duration(oldest * float64(time.Second))}, nil
}
