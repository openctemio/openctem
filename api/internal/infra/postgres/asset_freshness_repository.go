package postgres

// Asset freshness records (docs/architecture/asset-freshness.md): the last
// observation of each enrichable attribute class of an asset.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetFreshnessRepository stores asset_attribute_freshness rows.
type AssetFreshnessRepository struct {
	db *DB
}

// NewAssetFreshnessRepository creates the repository.
func NewAssetFreshnessRepository(db *DB) *AssetFreshnessRepository {
	return &AssetFreshnessRepository{db: db}
}

var _ assetfreshness.Repository = (*AssetFreshnessRepository)(nil)

// maxFreshnessSource bounds the stored tool name (column varchar(100)).
const maxFreshnessSource = 100

// Record upserts the observations in one statement. An asset id that is not
// the tenant's matches no asset and is skipped (the INSERT selects from the
// tenant's assets), so a caller can never write another tenant's rows. A
// stored observation newer than the incoming one is kept; an observation in
// the future is clamped to now.
func (r *AssetFreshnessRepository) Record(ctx context.Context, tenantID shared.ID, obs []assetfreshness.Observation) error {
	if len(obs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	// One row per (asset, class): the newest observation in the batch wins,
	// so ON CONFLICT never sees the same key twice in one statement.
	type key struct {
		asset shared.ID
		class assetfreshness.Class
	}
	newest := make(map[key]assetfreshness.Observation, len(obs))
	for _, o := range obs {
		if _, ok := assetfreshness.Lookup(o.Class); !ok || o.AssetID.IsZero() {
			continue
		}
		if o.ObservedAt.IsZero() || o.ObservedAt.After(now) {
			o.ObservedAt = now
		}
		k := key{o.AssetID, o.Class}
		if prev, ok := newest[k]; !ok || o.ObservedAt.After(prev.ObservedAt) {
			newest[k] = o
		}
	}
	if len(newest) == 0 {
		return nil
	}
	ids := make([]string, 0, len(newest))
	classes := make([]string, 0, len(newest))
	ats := make([]time.Time, 0, len(newest))
	sources := make([]string, 0, len(newest))
	for k, o := range newest {
		src := strings.TrimSpace(o.Source)
		if len(src) > maxFreshnessSource {
			src = src[:maxFreshnessSource]
		}
		ids = append(ids, k.asset.String())
		classes = append(classes, string(k.class))
		ats = append(ats, o.ObservedAt.UTC())
		sources = append(sources, src)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_attribute_freshness (tenant_id, asset_id, class, observed_at, source, updated_at)
		SELECT a.tenant_id, a.id, v.class, v.observed_at, v.source, $6
		  FROM unnest($2::uuid[], $3::text[], $4::timestamptz[], $5::text[]) AS v(asset_id, class, observed_at, source)
		  JOIN assets a ON a.tenant_id = $1 AND a.id = v.asset_id
		ON CONFLICT ON CONSTRAINT pk_asset_attribute_freshness DO UPDATE SET
		       observed_at = EXCLUDED.observed_at,
		       source      = EXCLUDED.source,
		       updated_at  = EXCLUDED.updated_at
		 WHERE asset_attribute_freshness.observed_at <= EXCLUDED.observed_at`,
		tenantID.String(), pq.Array(ids), pq.Array(classes), pq.Array(ats), pq.Array(sources), now)
	if err != nil {
		return fmt.Errorf("record asset freshness: %w", err)
	}
	return nil
}

// ListForAsset returns the asset's observations, tenant-scoped.
func (r *AssetFreshnessRepository) ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]assetfreshness.Observation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT class, observed_at, source
		  FROM asset_attribute_freshness
		 WHERE tenant_id = $1 AND asset_id = $2
		 ORDER BY class`, tenantID.String(), assetID.String())
	if err != nil {
		return nil, fmt.Errorf("list asset freshness: %w", err)
	}
	defer rows.Close()
	var out []assetfreshness.Observation
	for rows.Next() {
		o := assetfreshness.Observation{AssetID: assetID}
		var class string
		if err := rows.Scan(&class, &o.ObservedAt, &o.Source); err != nil {
			return nil, fmt.Errorf("scan asset freshness: %w", err)
		}
		o.Class = assetfreshness.Class(class)
		out = append(out, o)
	}
	return out, rows.Err()
}
