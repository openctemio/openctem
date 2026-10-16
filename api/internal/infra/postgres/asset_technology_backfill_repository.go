package postgres

// The asset technology backfill's view of the database
// (docs/rfcs/RFC-112-asset-technologies.md §3.7).

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	assettechapp "github.com/openctemio/openctem/api/internal/app/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetTechnologyBackfillRepository reads assets and component links for
// the backfill, a batch at a time.
type AssetTechnologyBackfillRepository struct {
	db *DB
}

// NewAssetTechnologyBackfillRepository creates the repository.
func NewAssetTechnologyBackfillRepository(db *DB) *AssetTechnologyBackfillRepository {
	return &AssetTechnologyBackfillRepository{db: db}
}

var _ assettechapp.BackfillStore = (*AssetTechnologyBackfillRepository)(nil)

// PendingTenants returns tenants with assets not backfilled at version.
func (r *AssetTechnologyBackfillRepository) PendingTenants(ctx context.Context, version int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id)
		  AND NOT EXISTS (SELECT 1 FROM asset_technology_backfill b WHERE b.tenant_id = t.id AND b.version >= $1)
		ORDER BY t.id`, version)
	if err != nil {
		return nil, fmt.Errorf("list tenants to backfill technologies: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// ScanAssets returns the tenant's next assets with stored technologies,
// after afterID in id order, with what set reconciliation recorded about
// each element.
func (r *AssetTechnologyBackfillRepository) ScanAssets(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]assettechapp.BackfillAsset, error) {
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.properties -> 'technologies', a.first_seen, a.last_seen,
		       COALESCE((SELECT jsonb_agg(jsonb_build_object('e', e.element, 'f', e.first_seen, 'l', e.last_seen, 's', e.source_name)
		                                  ORDER BY e.last_seen)
		                   FROM asset_attribute_set_elements e
		                  WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id
		                    AND e.attribute = 'technologies' AND e.removed_at IS NULL), '[]'::jsonb)
		  FROM assets a
		 WHERE a.tenant_id = $1 AND a.id > $2::uuid
		   AND jsonb_typeof(a.properties -> 'technologies') = 'array'
		 ORDER BY a.id
		 LIMIT $3`, tenantID.String(), afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("scan assets for technology backfill: %w", err)
	}
	defer rows.Close()
	var out []assettechapp.BackfillAsset
	for rows.Next() {
		var id string
		var techRaw, seenRaw []byte
		var first, last time.Time
		if err := rows.Scan(&id, &techRaw, &first, &last, &seenRaw); err != nil {
			return nil, fmt.Errorf("scan asset for technology backfill: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		a := assettechapp.BackfillAsset{ID: aid, FirstSeen: first, LastSeen: last, Elements: technologyElementsOf(techRaw)}
		var seen []struct {
			E string    `json:"e"`
			F time.Time `json:"f"`
			L time.Time `json:"l"`
			S string    `json:"s"`
		}
		if json.Unmarshal(seenRaw, &seen) == nil && len(seen) > 0 {
			a.Seen = make(map[string]assettechapp.BackfillElement, len(seen))
			for _, s := range seen {
				prev, ok := a.Seen[s.E]
				el := assettechapp.BackfillElement{Element: s.E, FirstSeen: s.F, LastSeen: s.L, Source: s.S}
				if ok && prev.FirstSeen.Before(el.FirstSeen) {
					el.FirstSeen = prev.FirstSeen
				}
				a.Seen[s.E] = el // ordered by last_seen: the latest source wins
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// technologyElementsOf reads properties.technologies as "Name:version"
// strings (a list of strings or of {name, version} objects).
func technologyElementsOf(raw []byte) []string {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		var s string
		if json.Unmarshal(item, &s) == nil {
			out = append(out, s)
			continue
		}
		var obj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(item, &obj) == nil && obj.Name != "" {
			if obj.Version != "" {
				out = append(out, obj.Name+":"+obj.Version)
			} else {
				out = append(out, obj.Name)
			}
		}
	}
	return out
}

// ScanTechnologyLinks returns the tenant's next component links whose
// source is a technology detection, after afterID in id order.
func (r *AssetTechnologyBackfillRepository) ScanTechnologyLinks(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]assettechapp.BackfillLink, error) {
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, p.name, v.raw, p.cpe_vendor IS NOT NULL
		  FROM asset_software s
		  JOIN software_products p ON p.id = s.product_id
		  JOIN software_versions v ON v.id = s.software_version_id
		 WHERE s.tenant_id = $1 AND s.source = 'technology' AND s.id > $2::uuid
		 ORDER BY s.id
		 LIMIT $3`, tenantID.String(), afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("scan technology links: %w", err)
	}
	defer rows.Close()
	var out []assettechapp.BackfillLink
	for rows.Next() {
		var id string
		var l assettechapp.BackfillLink
		if err := rows.Scan(&id, &l.Product, &l.Version, &l.HasCPE); err != nil {
			return nil, fmt.Errorf("scan technology link: %w", err)
		}
		if l.ID, err = shared.IDFromString(id); err != nil {
			continue
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// DeleteLinks deletes the tenant's component links by id, technology links
// only.
func (r *AssetTechnologyBackfillRepository) DeleteLinks(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	list := make([]string, 0, len(ids))
	for _, id := range ids {
		list = append(list, id.String())
	}
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM asset_software
		 WHERE tenant_id = $1 AND source = 'technology' AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(list))
	if err != nil {
		return 0, fmt.Errorf("delete technology links: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkBackfilled records that a tenant was backfilled at version.
func (r *AssetTechnologyBackfillRepository) MarkBackfilled(ctx context.Context, tenantID shared.ID, version int, stats assettechapp.BackfillStats) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_technology_backfill (tenant_id, version, assets_scanned, technologies, links_removed, completed_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (tenant_id) DO UPDATE SET
		       version = EXCLUDED.version, assets_scanned = EXCLUDED.assets_scanned,
		       technologies = EXCLUDED.technologies, links_removed = EXCLUDED.links_removed,
		       completed_at = EXCLUDED.completed_at`,
		tenantID.String(), version, stats.AssetsScanned, stats.Technologies, stats.LinksRemoved)
	if err != nil {
		return fmt.Errorf("mark technology backfill: %w", err)
	}
	return nil
}
