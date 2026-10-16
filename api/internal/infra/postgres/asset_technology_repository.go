package postgres

// Asset technologies (docs/rfcs/RFC-112-asset-technologies.md): what a
// fingerprinting probe detected on an asset, with its category.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetTechnologyRepository stores asset_technologies rows.
type AssetTechnologyRepository struct {
	db *DB
}

// NewAssetTechnologyRepository creates the repository.
func NewAssetTechnologyRepository(db *DB) *AssetTechnologyRepository {
	return &AssetTechnologyRepository{db: db}
}

var _ assettech.Repository = (*AssetTechnologyRepository)(nil)

// Enrich adds what a report knew about technologies the assets already
// show: the tool's category (never replacing a known one with other), its
// confidence, the source and the last sighting. It updates existing rows
// only, matched on the tenant, so it can neither add a technology nor
// touch another tenant's rows.
func (r *AssetTechnologyRepository) Enrich(ctx context.Context, tenantID shared.ID, techs []assettech.Technology) error {
	techs = dedupTechnologies(techs)
	if len(techs) == 0 {
		return nil
	}
	n := len(techs)
	ids, keys, cats, sources := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	confs := make([]int64, 0, n)
	lasts := make([]time.Time, 0, n)
	for _, t := range techs {
		ids = append(ids, t.AssetID.String())
		keys = append(keys, t.Key)
		cats = append(cats, string(t.Category))
		confs = append(confs, int64(t.Confidence))
		sources = append(sources, t.Source)
		lasts = append(lasts, t.LastSeen.UTC())
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE asset_technologies t SET
		       category   = CASE WHEN v.category <> 'other' THEN v.category ELSE t.category END,
		       confidence = CASE WHEN v.confidence > 0 THEN v.confidence ELSE t.confidence END,
		       source     = CASE WHEN v.source <> '' THEN v.source ELSE t.source END,
		       last_seen  = GREATEST(t.last_seen, v.last_seen),
		       updated_at = now()
		  FROM unnest($2::uuid[], $3::text[], $4::text[], $5::int[], $6::text[], $7::timestamptz[])
		       AS v(asset_id, name_key, category, confidence, source, last_seen)
		 WHERE t.tenant_id = $1 AND t.asset_id = v.asset_id AND t.name_key = v.name_key`,
		tenantID.String(), pq.Array(ids), pq.Array(keys), pq.Array(cats), pq.Array(confs), pq.Array(sources), pq.Array(lasts))
	if err != nil {
		return fmt.Errorf("enrich asset technologies: %w", err)
	}
	return nil
}

// ListByAsset returns the asset's technologies, tenant-scoped.
func (r *AssetTechnologyRepository) ListByAsset(ctx context.Context, tenantID, assetID shared.ID) ([]assettech.Technology, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT name_key, name, version, category, confidence, source, first_seen, last_seen
		  FROM asset_technologies
		 WHERE tenant_id = $1 AND asset_id = $2
		 ORDER BY category, name_key
		 LIMIT $3`, tenantID.String(), assetID.String(), assettech.MaxListed)
	if err != nil {
		return nil, fmt.Errorf("list asset technologies: %w", err)
	}
	defer rows.Close()
	var out []assettech.Technology
	for rows.Next() {
		t := assettech.Technology{AssetID: assetID}
		var cat string
		if err := rows.Scan(&t.Key, &t.Name, &t.Version, &cat, &t.Confidence, &t.Source, &t.FirstSeen, &t.LastSeen); err != nil {
			return nil, fmt.Errorf("scan asset technology: %w", err)
		}
		t.Category = assettech.Category(cat)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListByAssets returns, for each of the tenant's assets, at most perAsset
// of its technologies ordered by category and name.
func (r *AssetTechnologyRepository) ListByAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, perAsset int) (map[shared.ID][]assettech.Technology, error) {
	out := map[shared.ID][]assettech.Technology{}
	if len(assetIDs) == 0 || perAsset <= 0 {
		return out, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT asset_id, name_key, name, version, category, confidence, source, first_seen, last_seen
		  FROM (SELECT t.*, row_number() OVER (PARTITION BY asset_id ORDER BY category, name_key) AS rn
		          FROM asset_technologies t
		         WHERE t.tenant_id = $1 AND t.asset_id = ANY($2::uuid[])) x
		 WHERE rn <= $3
		 ORDER BY asset_id, category, name_key`, tenantID.String(), pq.Array(ids), perAsset)
	if err != nil {
		return nil, fmt.Errorf("list technologies of assets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, cat string
		var t assettech.Technology
		if err := rows.Scan(&id, &t.Key, &t.Name, &t.Version, &cat, &t.Confidence, &t.Source, &t.FirstSeen, &t.LastSeen); err != nil {
			return nil, fmt.Errorf("scan technology of assets: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		t.AssetID, t.Category = aid, assettech.Category(cat)
		out[aid] = append(out[aid], t)
	}
	return out, rows.Err()
}

// shownTechnologiesSQL is an asset's technologies in stored element form
// ("Name" or "Name:version"), as a JSON array, for the set lock query.
const shownTechnologiesSQL = `COALESCE((SELECT jsonb_agg(CASE WHEN t.version = '' THEN t.name ELSE t.name || ':' || t.version END
		ORDER BY t.name_key) FROM asset_technologies t WHERE t.tenant_id = assets.tenant_id AND t.asset_id = assets.id), 'null'::jsonb)`

// writeAssetTechnologiesTx makes the asset's technologies the resolved,
// collapsed set, in the transaction that resolved it: rows for technologies
// no longer shown are deleted, new ones are inserted (categorized by name;
// ingest adds the tool's category afterwards) and a changed version is
// updated. The retired properties.technologies key is removed.
func writeAssetTechnologiesTx(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, elements []string, now time.Time) error {
	keys, names, versions, cats := make([]string, 0, len(elements)), make([]string, 0, len(elements)),
		make([]string, 0, len(elements)), make([]string, 0, len(elements))
	for _, e := range elements {
		name, version := assettech.Split(e)
		k := assettech.Key(name)
		if k == "" {
			continue
		}
		keys = append(keys, k)
		names = append(names, name)
		versions = append(versions, version)
		cats = append(cats, string(assettech.Classify(k, nil)))
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_technologies
		 WHERE tenant_id = $1 AND asset_id = $2 AND NOT (name_key = ANY($3::text[]))`,
		tenantID.String(), assetID.String(), pq.Array(keys)); err != nil {
		return fmt.Errorf("prune asset technologies: %w", err)
	}
	if len(keys) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_technologies (tenant_id, asset_id, name_key, name, version, category, first_seen, last_seen)
			SELECT a.tenant_id, a.id, v.name_key, v.name, v.version, v.category, $6, $6
			  FROM unnest($3::text[], $4::text[], $5::text[], $7::text[]) AS v(name_key, name, version, category)
			  JOIN assets a ON a.tenant_id = $1 AND a.id = $2
			ON CONFLICT ON CONSTRAINT pk_asset_technologies DO UPDATE SET
			       name = EXCLUDED.name, version = EXCLUDED.version, updated_at = now()
			 WHERE (asset_technologies.name, asset_technologies.version) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.version)`,
			tenantID.String(), assetID.String(), pq.Array(keys), pq.Array(names), pq.Array(versions), now.UTC(), pq.Array(cats)); err != nil {
			return fmt.Errorf("write asset technologies: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets SET properties = properties - 'technologies'
		 WHERE tenant_id = $1 AND id = $2 AND properties ? 'technologies'`,
		tenantID.String(), assetID.String()); err != nil {
		return fmt.Errorf("drop retired technologies property: %w", err)
	}
	return nil
}

// dedupTechnologies keeps one technology per (asset, key), so one
// statement never meets the same key twice: the latest sighting wins, a
// known category and the highest confidence are kept.
func dedupTechnologies(in []assettech.Technology) []assettech.Technology {
	type k struct {
		asset shared.ID
		key   string
	}
	idx := make(map[k]int, len(in))
	out := make([]assettech.Technology, 0, len(in))
	for _, t := range in {
		if t.AssetID.IsZero() || t.Key == "" || !t.Category.IsValid() {
			continue
		}
		key := k{t.AssetID, t.Key}
		i, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, t)
			continue
		}
		prev := out[i]
		if t.Category == assettech.CategoryOther {
			t.Category = prev.Category
		}
		if t.Confidence < prev.Confidence {
			t.Confidence = prev.Confidence
		}
		if prev.LastSeen.After(t.LastSeen) {
			t.LastSeen = prev.LastSeen
		}
		out[i] = t
	}
	return out
}
