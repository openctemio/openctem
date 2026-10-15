package postgres

// Asset risk rescore queue (docs/architecture/asset-risk-score.md). Rows are
// written by database triggers (migration asset_risk_queue) and claimed by
// the asset-risk-score worker.

import (
	"context"
	"database/sql"
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

// riskReconcileBatch is how many assets one reconcile statement queues.
const riskReconcileBatch = 5000

// EnqueueAllForPlatform queues every live asset with a later due time,
// tenant by tenant in id-ordered batches so no statement holds many rows.
// An asset already queued keeps its row (DO NOTHING), so a real change is
// never pushed back. A batch that races a concurrent asset delete (foreign
// key violation) is retried: its next snapshot no longer sees the asset.
func (r *AssetRiskQueueRepository) EnqueueAllForPlatform(ctx context.Context, delay time.Duration) (int64, error) {
	if delay < 0 {
		delay = 0
	}
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return 0, err
	}

	const q = `
		WITH batch AS (
			SELECT a.id, a.tenant_id FROM assets a
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.id > $2::uuid
			ORDER BY a.id
			LIMIT $3
		), ins AS (
			INSERT INTO asset_risk_queue (asset_id, tenant_id, enqueued_at)
			SELECT b.id, b.tenant_id, now() + make_interval(secs => $4) FROM batch b
			ORDER BY b.id
			ON CONFLICT (asset_id) DO NOTHING
			RETURNING 1
		)
		SELECT (SELECT COUNT(*) FROM batch),
		       COALESCE((SELECT b.id::text FROM batch b ORDER BY b.id DESC LIMIT 1), ''),
		       (SELECT COUNT(*) FROM ins)`
	var total int64
	for _, tid := range tenants {
		after := "00000000-0000-0000-0000-000000000000"
		for {
			var (
				seen, queued int64
				last         string
			)
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				err = r.db.QueryRowContext(ctx, q, tid, after, riskReconcileBatch, delay.Seconds()).Scan(&seen, &last, &queued)
				if !isForeignKeyViolation(err) {
					break
				}
			}
			if err != nil {
				return total, fmt.Errorf("enqueue risk reconcile: %w", err)
			}
			total += queued
			if seen < riskReconcileBatch || last == "" {
				break
			}
			after = last
		}
	}
	return total, nil
}

// tenantIDs lists every tenant id.
func (r *AssetRiskQueueRepository) tenantIDs(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants for risk reconcile: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return tenants, nil
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

var _ asset.RiskContributorReader = (*AssetRiskQueueRepository)(nil)

// TopContributors returns the worst active findings of one asset of the
// tenant.
func (r *AssetRiskQueueRepository) TopContributors(ctx context.Context, tenantID, assetID shared.ID, limit int) ([]asset.RiskContributor, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	q := `
		SELECT f.id, COALESCE(NULLIF(f.title, ''), f.message), f.severity, f.epss_score,
		       COALESCE(f.is_in_kev, false), f.exploit_available
		FROM findings f
		WHERE f.tenant_id = $1 AND f.asset_id = $2 AND NOT f.branch_only
		  AND ` + riskBearingFindingStatusClause + `
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         COALESCE(f.is_in_kev, false) DESC, f.exploit_available DESC,
		         COALESCE(f.epss_score, 0) DESC, f.id
		LIMIT $3`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), assetID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("risk contributors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]asset.RiskContributor, 0, limit)
	for rows.Next() {
		var (
			id, title, sev string
			epss           sql.NullFloat64
			kev, exploit   bool
		)
		if err := rows.Scan(&id, &title, &sev, &epss, &kev, &exploit); err != nil {
			return nil, fmt.Errorf("scan risk contributor: %w", err)
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		c := asset.RiskContributor{FindingID: fid, Title: title, Severity: sev, InKEV: kev, ExploitAvailable: exploit}
		if epss.Valid {
			v := epss.Float64
			c.EPSSScore = &v
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate risk contributors: %w", err)
	}
	return out, nil
}

// RefreshRollups recomputes the stored roll-ups of the business units and
// asset groups that contain any of the given assets of the tenant: a unit's
// average risk score and open (active) finding counts, a group's average
// risk score. Called after a rescore so the roll-ups follow the asset scores.
func (r *AssetRiskQueueRepository) RefreshRollups(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	bu := `
		UPDATE business_units bu SET
			finding_count = COALESCE((
				SELECT COUNT(*) FROM findings f
				JOIN business_unit_assets bua ON bua.asset_id = f.asset_id AND bua.tenant_id = f.tenant_id
				WHERE bua.business_unit_id = bu.id AND bua.tenant_id = $1 AND NOT f.branch_only AND ` + riskBearingFindingStatusClause + `
			), 0),
			critical_finding_count = COALESCE((
				SELECT COUNT(*) FROM findings f
				JOIN business_unit_assets bua ON bua.asset_id = f.asset_id AND bua.tenant_id = f.tenant_id
				WHERE bua.business_unit_id = bu.id AND bua.tenant_id = $1 AND NOT f.branch_only AND f.severity = 'critical'
				  AND ` + riskBearingFindingStatusClause + `
			), 0),
			avg_risk_score = COALESCE((
				SELECT AVG(a.risk_score) FROM business_unit_assets bua
				JOIN assets a ON a.id = bua.asset_id AND a.tenant_id = bua.tenant_id AND a.deleted_at IS NULL
				WHERE bua.business_unit_id = bu.id AND bua.tenant_id = $1
			), 0)
		WHERE bu.tenant_id = $1 AND bu.id IN (
			SELECT bua.business_unit_id FROM business_unit_assets bua
			WHERE bua.tenant_id = $1 AND bua.asset_id = ANY($2::uuid[]))`
	if _, err := r.db.ExecContext(ctx, bu, tenantID.String(), pq.Array(ids)); err != nil {
		return fmt.Errorf("refresh business unit roll-ups: %w", err)
	}
	grp := `
		UPDATE asset_groups g SET
			risk_score = COALESCE((
				SELECT AVG(a.risk_score)::integer FROM ` + groupMembersFrom + `
				WHERE agm.asset_group_id = g.id
			), 0)
		WHERE g.tenant_id = $1 AND g.id IN (
			SELECT agm.asset_group_id FROM asset_group_members agm
			JOIN assets a ON a.id = agm.asset_id AND a.tenant_id = $1
			WHERE agm.asset_id = ANY($2::uuid[]))`
	if _, err := r.db.ExecContext(ctx, grp, tenantID.String(), pq.Array(ids)); err != nil {
		return fmt.Errorf("refresh asset group roll-ups: %w", err)
	}
	return nil
}
