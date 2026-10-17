package postgres

// Asset technologies (docs/rfcs/RFC-112-asset-technologies.md): what a
// fingerprinting probe detected on an asset, with its category.

import (
	"context"
	"database/sql"
	"encoding/json"
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

// Upsert records the technologies in one statement. An asset id that is
// not the tenant's matches no asset and is skipped (the INSERT selects from
// the tenant's assets), so a caller can never write another tenant's rows.
func (r *AssetTechnologyRepository) Upsert(ctx context.Context, tenantID shared.ID, techs []assettech.Technology) error {
	techs = dedupTechnologies(techs)
	if len(techs) == 0 {
		return nil
	}
	n := len(techs)
	ids, keys, names, versions := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	cats, sources := make([]string, 0, n), make([]string, 0, n)
	confs := make([]int64, 0, n)
	firsts, lasts := make([]time.Time, 0, n), make([]time.Time, 0, n)
	for _, t := range techs {
		ids = append(ids, t.AssetID.String())
		keys = append(keys, t.Key)
		names = append(names, t.Name)
		versions = append(versions, t.Version)
		cats = append(cats, string(t.Category))
		confs = append(confs, int64(t.Confidence))
		sources = append(sources, t.Source)
		firsts = append(firsts, t.FirstSeen.UTC())
		lasts = append(lasts, t.LastSeen.UTC())
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_technologies
		       (tenant_id, asset_id, name_key, name, version, category, confidence, source, first_seen, last_seen, updated_at)
		SELECT a.tenant_id, a.id, v.name_key, v.name, v.version, v.category, v.confidence, v.source,
		       v.first_seen, GREATEST(v.first_seen, v.last_seen), now()
		  FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::int[], $8::text[],
		              $9::timestamptz[], $10::timestamptz[])
		       AS v(asset_id, name_key, name, version, category, confidence, source, first_seen, last_seen)
		  JOIN assets a ON a.tenant_id = $1 AND a.id = v.asset_id
		ON CONFLICT ON CONSTRAINT pk_asset_technologies DO UPDATE SET
		       name       = EXCLUDED.name,
		       version    = CASE WHEN EXCLUDED.version <> '' THEN EXCLUDED.version ELSE asset_technologies.version END,
		       category   = CASE WHEN EXCLUDED.category <> 'other' THEN EXCLUDED.category ELSE asset_technologies.category END,
		       confidence = CASE WHEN EXCLUDED.confidence > 0 THEN EXCLUDED.confidence ELSE asset_technologies.confidence END,
		       source     = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE asset_technologies.source END,
		       first_seen = LEAST(asset_technologies.first_seen, EXCLUDED.first_seen),
		       last_seen  = GREATEST(asset_technologies.last_seen, EXCLUDED.last_seen),
		       updated_at = now()`,
		tenantID.String(), pq.Array(ids), pq.Array(keys), pq.Array(names), pq.Array(versions), pq.Array(cats),
		pq.Array(confs), pq.Array(sources), pq.Array(firsts), pq.Array(lasts))
	if err != nil {
		return fmt.Errorf("upsert asset technologies: %w", err)
	}
	return r.trimOverCap(ctx, tenantID, ids)
}

// trimOverCap enforces assettech.MaxPerAsset on what is stored, not only on
// what one report may send: rows past the cap are deleted for the assets just
// written, the oldest last_seen first. It runs whether or not set
// reconciliation is wired, so accumulated sightings cannot grow without bound.
func (r *AssetTechnologyRepository) trimOverCap(ctx context.Context, tenantID shared.ID, assetIDs []string) error {
	if _, err := r.db.ExecContext(ctx, `
		DELETE FROM asset_technologies t
		 USING (SELECT asset_id, name_key,
		               row_number() OVER (PARTITION BY asset_id ORDER BY last_seen DESC, name_key) AS rn
		          FROM asset_technologies
		         WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])) x
		 WHERE t.tenant_id = $1 AND t.asset_id = x.asset_id AND t.name_key = x.name_key AND x.rn > $3`,
		tenantID.String(), pq.Array(assetIDs), assettech.MaxPerAsset); err != nil {
		return fmt.Errorf("trim asset technologies: %w", err)
	}
	return nil
}

// dedupTechnologies keeps one technology per (asset, key), so ON CONFLICT
// never meets the same key twice in one statement: the latest sighting
// wins, a known version, category and confidence are kept.
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
		if t.Version == "" {
			t.Version = prev.Version
		}
		if t.Category == assettech.CategoryOther {
			t.Category = prev.Category
		}
		if t.Confidence < prev.Confidence {
			t.Confidence = prev.Confidence
		}
		if prev.FirstSeen.Before(t.FirstSeen) {
			t.FirstSeen = prev.FirstSeen
		}
		if prev.LastSeen.After(t.LastSeen) {
			t.LastSeen = prev.LastSeen
		}
		out[i] = t
	}
	return out
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

// ShownKeys returns, for each of the tenant's assets, the keys of the
// technologies its reconciled properties.technologies shows. An asset with
// none maps to an empty set; an id that is not the tenant's is absent.
func (r *AssetTechnologyRepository) ShownKeys(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]map[string]bool, error) {
	out := map[shared.ID]map[string]bool{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, COALESCE(properties -> 'technologies', 'null'::jsonb)
		  FROM assets
		 WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read shown technologies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("scan shown technologies: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		out[aid] = technologyKeysOf(raw)
	}
	return out, rows.Err()
}

// technologyKeysOf reads the keys of a properties.technologies value: a
// list of "Name:version" strings or of {name, version} objects.
func technologyKeysOf(raw []byte) map[string]bool {
	keys := map[string]bool{}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		var one string
		if json.Unmarshal(raw, &one) == nil {
			if k := assettech.ElementKey(one); k != "" {
				keys[k] = true
			}
		}
		return keys
	}
	for _, item := range list {
		var s string
		if json.Unmarshal(item, &s) == nil {
			if k := assettech.ElementKey(s); k != "" {
				keys[k] = true
			}
			continue
		}
		var obj struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(item, &obj) == nil {
			if k := assettech.Key(obj.Name); k != "" {
				keys[k] = true
			}
		}
	}
	return keys
}

// pruneAssetTechnologiesTx deletes the asset's technologies its reconciled
// set no longer shows, in the transaction that wrote the set.
func pruneAssetTechnologiesTx(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, elements []string) error {
	keep := make([]string, 0, len(elements))
	for _, e := range elements {
		if k := assettech.ElementKey(e); k != "" {
			keep = append(keep, k)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_technologies
		 WHERE tenant_id = $1 AND asset_id = $2 AND NOT (name_key = ANY($3::text[]))`,
		tenantID.String(), assetID.String(), pq.Array(keep)); err != nil {
		return fmt.Errorf("prune asset technologies: %w", err)
	}
	return nil
}
