package postgres

// Resolution state of host names (asset_resolution).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetResolutionRepository stores asset_resolution rows.
type AssetResolutionRepository struct {
	db *DB
}

// NewAssetResolutionRepository creates the repository.
func NewAssetResolutionRepository(db *DB) *AssetResolutionRepository {
	return &AssetResolutionRepository{db: db}
}

var _ assetresolution.Store = (*AssetResolutionRepository)(nil)

const maxResolutionBatch = 20000

func resolutionIDs(ids []shared.ID) ([]string, error) {
	if len(ids) > maxResolutionBatch {
		return nil, fmt.Errorf("asset resolution: %d assets, at most %d", len(ids), maxResolutionBatch)
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out, nil
}

func clampObserved(at time.Time) time.Time {
	if at.IsZero() || at.After(time.Now()) {
		return time.Now()
	}
	return at
}

// RecordResolved marks the tenant's assets resolving. The INSERT selects
// from the tenant's live assets, so another tenant's id writes nothing. An
// older observation never overwrites a newer one.
func (r *AssetResolutionRepository) RecordResolved(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, at time.Time) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids, err := resolutionIDs(assetIDs)
	if err != nil {
		return err
	}
	at = clampObserved(at)
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO asset_resolution (tenant_id, asset_id, state, resolved_at, checked_at, failures, source)
		SELECT a.tenant_id, a.id, 'resolving', $3, $3, 0, $4
		  FROM assets a
		 WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL
		ON CONFLICT (tenant_id, asset_id) DO UPDATE
		   SET state = 'resolving', resolved_at = EXCLUDED.resolved_at, checked_at = EXCLUDED.checked_at,
		       failures = 0, source = EXCLUDED.source
		 WHERE asset_resolution.checked_at <= EXCLUDED.checked_at`,
		tenantID.String(), pq.Array(ids), at, assetresolution.SourceObservation)
	if err != nil {
		return fmt.Errorf("record resolved names: %w", err)
	}
	return nil
}

const recordFailedSQL = `
	INSERT INTO asset_resolution (tenant_id, asset_id, state, resolved_at, checked_at, failures, source)
	SELECT a.tenant_id, a.id,
	       CASE WHEN 1 >= $5 THEN 'not_resolving' ELSE 'resolving' END,
	       NULL, $3, 1, $4
	  FROM assets a
	 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND %s
	ON CONFLICT (tenant_id, asset_id) DO UPDATE
	   SET failures = asset_resolution.failures + 1,
	       state = CASE WHEN asset_resolution.failures + 1 >= $5 THEN 'not_resolving' ELSE asset_resolution.state END,
	       checked_at = EXCLUDED.checked_at, source = EXCLUDED.source
	 WHERE asset_resolution.checked_at < EXCLUDED.checked_at`

// RecordFailed counts a failed check for the tenant's assets.
func (r *AssetResolutionRepository) RecordFailed(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, at time.Time, source string) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids, err := resolutionIDs(assetIDs)
	if err != nil {
		return err
	}
	if _, err := r.db.ExecContext(ctx, fmt.Sprintf(recordFailedSQL, "a.id = ANY($2::uuid[])"),
		tenantID.String(), pq.Array(ids), clampObserved(at), source, assetresolution.NotResolvingAfter); err != nil {
		return fmt.Errorf("record failed resolution: %w", err)
	}
	return nil
}

// RecordFailedNames counts a failed check for the tenant's assets named so.
func (r *AssetResolutionRepository) RecordFailedNames(ctx context.Context, tenantID shared.ID, names []string, at time.Time, source string) error {
	if len(names) == 0 {
		return nil
	}
	if len(names) > maxResolutionBatch {
		return fmt.Errorf("asset resolution: %d names, at most %d", len(names), maxResolutionBatch)
	}
	if _, err := r.db.ExecContext(ctx, fmt.Sprintf(recordFailedSQL, "a.name = ANY($2::text[])"),
		tenantID.String(), pq.Array(names), clampObserved(at), source, assetresolution.NotResolvingAfter); err != nil {
		return fmt.Errorf("record failed resolution by name: %w", err)
	}
	return nil
}

// NotResolving returns which names belong to a not_resolving tenant asset.
func (r *AssetResolutionRepository) NotResolving(ctx context.Context, tenantID shared.ID, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.name
		  FROM assets a
		  JOIN asset_resolution ar ON ar.tenant_id = a.tenant_id AND ar.asset_id = a.id
		 WHERE a.tenant_id = $1 AND a.name = ANY($2::text[]) AND a.deleted_at IS NULL
		   AND ar.state = 'not_resolving'`, tenantID.String(), pq.Array(names))
	if err != nil {
		return nil, fmt.Errorf("read not-resolving names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan not-resolving name: %w", err)
		}
		out[n] = true
	}
	return out, rows.Err()
}

// Get returns the asset's state, nil when unknown.
func (r *AssetResolutionRepository) Get(ctx context.Context, tenantID, assetID shared.ID) (*assetresolution.Resolution, error) {
	var (
		res        assetresolution.Resolution
		state      string
		resolvedAt sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT state, resolved_at, checked_at, failures, source
		  FROM asset_resolution WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID.String(), assetID.String()).Scan(&state, &resolvedAt, &res.CheckedAt, &res.Failures, &res.Source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read asset resolution: %w", err)
	}
	res.AssetID, res.State = assetID, assetresolution.State(state)
	if resolvedAt.Valid {
		t := resolvedAt.Time
		res.ResolvedAt = &t
	}
	return &res, nil
}
