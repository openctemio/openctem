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

var _ assetfreshness.NameEvidenceReader = (*AssetFreshnessRepository)(nil)

// maxEvidenceNames bounds one evidence lookup (a run dispatches at most
// 10 000 targets).
const maxEvidenceNames = 10000

// FreshestByName returns, for each of the tenant's assets named in names,
// its freshest observation of the classes. Tenant-scoped: another tenant's
// asset of the same name is never read.
func (r *AssetFreshnessRepository) FreshestByName(ctx context.Context, tenantID shared.ID, names []string, classes []assetfreshness.Class) ([]assetfreshness.NameEvidence, error) {
	if len(names) == 0 || len(classes) == 0 {
		return nil, nil
	}
	if len(names) > maxEvidenceNames {
		return nil, fmt.Errorf("resolution evidence: %d names, at most %d", len(names), maxEvidenceNames)
	}
	cls := make([]string, len(classes))
	for i, c := range classes {
		cls[i] = string(c)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, max(f.observed_at)
		  FROM assets a
		  JOIN asset_attribute_freshness f ON f.tenant_id = a.tenant_id AND f.asset_id = a.id
		 WHERE a.tenant_id = $1 AND a.name = ANY($2) AND f.class = ANY($3)
		 GROUP BY a.id, a.name`, tenantID.String(), pq.Array(names), pq.Array(cls))
	if err != nil {
		return nil, fmt.Errorf("read resolution evidence: %w", err)
	}
	defer rows.Close()
	var out []assetfreshness.NameEvidence
	for rows.Next() {
		var e assetfreshness.NameEvidence
		var id string
		if err := rows.Scan(&id, &e.Name, &e.ObservedAt); err != nil {
			return nil, fmt.Errorf("scan resolution evidence: %w", err)
		}
		if e.AssetID, err = shared.IDFromString(id); err != nil {
			return nil, fmt.Errorf("scan resolution evidence: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
