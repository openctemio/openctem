package postgres

// Automatic enrichment requests (docs/architecture/asset-freshness.md).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetEnrichmentRequestRepository stores asset_enrichment_requests rows.
type AssetEnrichmentRequestRepository struct {
	db *DB
}

// NewAssetEnrichmentRequestRepository creates the repository.
func NewAssetEnrichmentRequestRepository(db *DB) *AssetEnrichmentRequestRepository {
	return &AssetEnrichmentRequestRepository{db: db}
}

var _ assetfreshness.RequestRepository = (*AssetEnrichmentRequestRepository)(nil)

func enrichmentIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !id.IsZero() {
			out = append(out, id.String())
		}
	}
	return out
}

// Request upserts one request per asset. The INSERT selects the tenant's own
// assets, so an id of another tenant opens nothing.
func (r *AssetEnrichmentRequestRepository) Request(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason assetfreshness.Reason, cooldown time.Duration) (int, error) {
	ids := enrichmentIDStrings(assetIDs)
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_enrichment_requests (tenant_id, asset_id, reason, requested_at)
		SELECT a.tenant_id, a.id, $3, now()
		  FROM assets a
		 WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL
		ON CONFLICT ON CONSTRAINT pk_asset_enrichment_requests DO UPDATE SET
		       reason = EXCLUDED.reason, requested_at = EXCLUDED.requested_at,
		       dispatched_at = NULL, outcome = ''
		 WHERE asset_enrichment_requests.dispatched_at IS NOT NULL
		   AND (EXCLUDED.reason = 'manual'
		        OR asset_enrichment_requests.dispatched_at < now() - make_interval(secs => $4))`,
		tenantID.String(), pq.Array(ids), string(reason), cooldown.Seconds())
	if err != nil {
		return 0, fmt.Errorf("request asset enrichment: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// TenantsDue lists tenants with pending requests past the debounce or at
// the burst size.
func (r *AssetEnrichmentRequestRepository) TenantsDue(ctx context.Context, debounce time.Duration, burst int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id
		  FROM asset_enrichment_requests
		 WHERE dispatched_at IS NULL
		 GROUP BY tenant_id
		HAVING min(requested_at) <= now() - make_interval(secs => $1) OR count(*) >= $2
		 ORDER BY min(requested_at)`, debounce.Seconds(), burst)
	if err != nil {
		return nil, fmt.Errorf("list tenants due for enrichment: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DispatchedSince counts requests the tenant had dispatched to a run since t.
func (r *AssetEnrichmentRequestRepository) DispatchedSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM asset_enrichment_requests
		 WHERE tenant_id = $1 AND dispatched_at >= $2 AND outcome = 'dispatched'`,
		tenantID.String(), t).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count dispatched enrichment: %w", err)
	}
	return n, nil
}

// Claim marks up to limit pending requests as claimed, oldest first. Rows
// another transaction holds are skipped, so two replicas never claim the
// same request.
func (r *AssetEnrichmentRequestRepository) Claim(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH c AS (
			SELECT asset_id FROM asset_enrichment_requests
			 WHERE tenant_id = $1 AND dispatched_at IS NULL
			 ORDER BY requested_at
			 LIMIT $2
			 FOR UPDATE SKIP LOCKED)
		UPDATE asset_enrichment_requests q
		   SET dispatched_at = now(), outcome = 'claimed', attempts = q.attempts + 1
		  FROM c
		 WHERE q.tenant_id = $1 AND q.asset_id = c.asset_id
		RETURNING q.asset_id`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("claim enrichment requests: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan claimed asset: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Settle records the outcome of claimed requests.
func (r *AssetEnrichmentRequestRepository) Settle(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, outcome assetfreshness.Outcome, runID *shared.ID) error {
	ids := enrichmentIDStrings(assetIDs)
	if len(ids) == 0 {
		return nil
	}
	var run any
	if runID != nil && !runID.IsZero() {
		run = runID.String()
	}
	if _, err := r.db.ExecContext(ctx, `
		UPDATE asset_enrichment_requests
		   SET outcome = $3, last_run_id = COALESCE($4::uuid, last_run_id)
		 WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND dispatched_at IS NOT NULL`,
		tenantID.String(), pq.Array(ids), string(outcome), run); err != nil {
		return fmt.Errorf("settle enrichment requests: %w", err)
	}
	return nil
}

// Get returns the asset's request, nil when there is none.
func (r *AssetEnrichmentRequestRepository) Get(ctx context.Context, tenantID, assetID shared.ID) (*assetfreshness.Request, error) {
	var (
		q      assetfreshness.Request
		reason string
		disp   sql.NullTime
		out    string
		run    sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT reason, requested_at, dispatched_at, outcome, last_run_id
		  FROM asset_enrichment_requests
		 WHERE tenant_id = $1 AND asset_id = $2`, tenantID.String(), assetID.String()).
		Scan(&reason, &q.RequestedAt, &disp, &out, &run)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get enrichment request: %w", err)
	}
	q.Reason, q.Outcome = assetfreshness.Reason(reason), assetfreshness.Outcome(out)
	if disp.Valid {
		t := disp.Time
		q.DispatchedAt = &t
	}
	if run.Valid {
		if id, err := shared.IDFromString(run.String); err == nil {
			q.LastRunID = &id
		}
	}
	return &q, nil
}
