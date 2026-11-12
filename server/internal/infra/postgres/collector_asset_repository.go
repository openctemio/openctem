package postgres

// Collector sources (migration collector_assets; RFC-040 §12): which assets
// each trusted collector source reported. Every query is scoped to the
// source's tenant, sensor, tool and instance; the composite foreign keys keep
// the asset and the sensor in that tenant.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CollectorAssetRepository implements ingest.CollectorAssetStore.
type CollectorAssetRepository struct {
	db *DB
}

// NewCollectorAssetRepository creates the repository.
func NewCollectorAssetRepository(db *DB) *CollectorAssetRepository {
	return &CollectorAssetRepository{db: db}
}

var _ ingest.CollectorAssetStore = (*CollectorAssetRepository)(nil)

// sightingBatch bounds one insert.
const sightingBatch = 1000

func collectorIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// OwnedAssets implements ingest.CollectorAssetStore: the ids the source
// created, that are not deleted, have no manual status override and no
// manual attribute lock.
func (r *CollectorAssetRepository) OwnedAssets(ctx context.Context, src ingest.CollectorSource, ids []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT ca.asset_id
		FROM collector_assets ca
		JOIN assets a ON a.tenant_id = ca.tenant_id AND a.id = ca.asset_id
		WHERE ca.tenant_id = $1 AND ca.sensor_id = $2 AND ca.tool = $3 AND ca.source_ref = $4
		  AND ca.asset_id = ANY($5::uuid[])
		  AND ca.created_asset
		  AND a.deleted_at IS NULL
		  AND NOT a.manual_status_override
		  AND NOT EXISTS (
		      SELECT 1 FROM asset_attribute_sources s
		      WHERE s.tenant_id = ca.tenant_id AND s.asset_id = ca.asset_id AND s.source_kind = 'manual')`,
		src.TenantID.String(), src.SensorID.String(), src.Tool, src.SourceRef, pq.Array(collectorIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("collector owned assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("collector owned assets: %w", err)
		}
		if parsed, err := shared.IDFromString(id); err == nil {
			out[parsed] = true
		}
	}
	return out, rows.Err()
}

// RecordSightings implements ingest.CollectorAssetStore. An asset of
// another tenant is never recorded (the insert selects it from the
// tenant's assets); created_asset only ever turns on.
func (r *CollectorAssetRepository) RecordSightings(ctx context.Context, src ingest.CollectorSource, observedAt time.Time, sightings []ingest.CollectorSighting) error {
	for start := 0; start < len(sightings); start += sightingBatch {
		end := min(start+sightingBatch, len(sightings))
		ids := make([]string, 0, end-start)
		created := make([]bool, 0, end-start)
		for _, s := range sightings[start:end] {
			ids = append(ids, s.AssetID.String())
			created = append(created, s.Created)
		}
		if _, err := r.db.ExecContext(ctx, `
			INSERT INTO collector_assets (tenant_id, sensor_id, tool, source_ref, asset_id, created_asset, first_seen, last_seen)
			SELECT $1, $2, $3, $4, a.id, x.created, $7, $7
			FROM unnest($5::uuid[], $6::boolean[]) AS x(asset_id, created)
			JOIN assets a ON a.tenant_id = $1 AND a.id = x.asset_id
			ON CONFLICT (tenant_id, sensor_id, tool, source_ref, asset_id) DO UPDATE
			SET created_asset = collector_assets.created_asset OR EXCLUDED.created_asset,
			    last_seen     = GREATEST(collector_assets.last_seen, EXCLUDED.last_seen),
			    first_seen    = LEAST(collector_assets.first_seen, EXCLUDED.first_seen),
			    missing_since = CASE WHEN EXCLUDED.last_seen >= collector_assets.last_seen
			                         THEN NULL ELSE collector_assets.missing_since END`,
			src.TenantID.String(), src.SensorID.String(), src.Tool, src.SourceRef,
			pq.Array(ids), pq.Array(created), observedAt.UTC()); err != nil {
			return fmt.Errorf("record collector sightings: %w", err)
		}
	}
	return nil
}

// MarkUnseen implements ingest.CollectorAssetStore in one transaction.
func (r *CollectorAssetRepository) MarkUnseen(ctx context.Context, src ingest.CollectorSource, observedAt time.Time,
	listed []shared.ID, guard ingest.BlindingGuard,
) (ingest.UnseenResult, error) {
	var res ingest.UnseenResult
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("collector sweep: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	args := []any{src.TenantID.String(), src.SensorID.String(), src.Tool, src.SourceRef, observedAt.UTC(), pq.Array(collectorIDStrings(listed))}
	// The source's own assets that are still listed as present.
	const owned = `
		FROM collector_assets ca
		JOIN assets a ON a.tenant_id = ca.tenant_id AND a.id = ca.asset_id
		WHERE ca.tenant_id = $1 AND ca.sensor_id = $2 AND ca.tool = $3 AND ca.source_ref = $4
		  AND ca.created_asset AND ca.missing_since IS NULL AND a.deleted_at IS NULL`
	// Of those, the ones this report does not list, that the source last
	// reported before it and that no source saw at or after its time.
	const unseen = owned + `
		  AND NOT (ca.asset_id = ANY($6::uuid[]))
		  AND ca.last_seen < $5 AND a.last_seen < $5`

	if err := tx.QueryRowContext(ctx, `SELECT count(*) `+owned, args[:4]...).Scan(&res.Owned); err != nil {
		return res, fmt.Errorf("collector sweep: count owned: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) `+unseen, args...).Scan(&res.Unseen); err != nil {
		return res, fmt.Errorf("collector sweep: count unseen: %w", err)
	}
	if res.Unseen == 0 {
		return res, nil
	}
	if guard.Holds(res.Unseen, res.Owned) {
		res.Held = true
		return res, nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE collector_assets ca SET missing_since = $5
		WHERE (ca.tenant_id, ca.sensor_id, ca.tool, ca.source_ref, ca.asset_id) IN (
		    SELECT ca.tenant_id, ca.sensor_id, ca.tool, ca.source_ref, ca.asset_id `+unseen+`)`, args...); err != nil {
		return res, fmt.Errorf("collector sweep: mark missing: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		UPDATE assets a SET status = 'stale', updated_at = now()
		FROM collector_assets ca
		WHERE ca.tenant_id = $1 AND ca.sensor_id = $2 AND ca.tool = $3 AND ca.source_ref = $4
		  AND ca.missing_since = $5 AND ca.created_asset
		  AND a.tenant_id = ca.tenant_id AND a.id = ca.asset_id
		  AND a.status = 'active' AND NOT a.manual_status_override AND a.deleted_at IS NULL
		RETURNING a.id`, src.TenantID.String(), src.SensorID.String(), src.Tool, src.SourceRef, observedAt.UTC())
	if err != nil {
		return res, fmt.Errorf("collector sweep: demote: %w", err)
	}
	if err := scanCollectorIDs(rows, &res.Demoted); err != nil {
		return res, fmt.Errorf("collector sweep: demote: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("collector sweep: commit: %w", err)
	}
	return res, nil
}

func scanCollectorIDs(rows *sql.Rows, out *[]shared.ID) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if parsed, err := shared.IDFromString(id); err == nil {
			*out = append(*out, parsed)
		}
	}
	return rows.Err()
}
