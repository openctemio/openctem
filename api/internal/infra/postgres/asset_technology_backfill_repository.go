package postgres

// The asset technology backfill's view of the database
// (docs/rfcs/RFC-112-asset-technologies.md §3.7).

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	assettechapp "github.com/openctemio/openctem/api/internal/app/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetTechnologyBackfillRepository reads technologies and component links
// for the backfill, a batch at a time.
type AssetTechnologyBackfillRepository struct {
	db *DB
}

// NewAssetTechnologyBackfillRepository creates the repository.
func NewAssetTechnologyBackfillRepository(db *DB) *AssetTechnologyBackfillRepository {
	return &AssetTechnologyBackfillRepository{db: db}
}

var _ assettechapp.BackfillStore = (*AssetTechnologyBackfillRepository)(nil)

const zeroUUID = "00000000-0000-0000-0000-000000000000"

// PendingTenants returns tenants with assets not backfilled at version. A
// tenant that only had a report-only run is pending again when enforce.
func (r *AssetTechnologyBackfillRepository) PendingTenants(ctx context.Context, version int, enforce bool) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id)
		  AND NOT EXISTS (SELECT 1 FROM asset_technology_backfill b WHERE b.tenant_id = t.id AND b.version >= $1 AND (b.enforced OR NOT $2::boolean))
		ORDER BY t.id`, version, enforce)
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

// ScanUnclassified returns the tenant's next technologies in category
// other, in (asset_id, name_key) order after the given position.
func (r *AssetTechnologyBackfillRepository) ScanUnclassified(ctx context.Context, tenantID shared.ID, afterAsset, afterKey string, limit int) ([]assettechapp.BackfillRow, error) {
	if afterAsset == "" {
		afterAsset = zeroUUID
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT asset_id, name_key FROM asset_technologies
		 WHERE tenant_id = $1 AND category = 'other' AND (asset_id, name_key) > ($2::uuid, $3::text)
		 ORDER BY asset_id, name_key
		 LIMIT $4`, tenantID.String(), afterAsset, afterKey, limit)
	if err != nil {
		return nil, fmt.Errorf("scan unclassified technologies: %w", err)
	}
	defer rows.Close()
	var out []assettechapp.BackfillRow
	for rows.Next() {
		var id string
		var row assettechapp.BackfillRow
		if err := rows.Scan(&id, &row.Key); err != nil {
			return nil, fmt.Errorf("scan unclassified technology: %w", err)
		}
		if row.AssetID, err = shared.IDFromString(id); err != nil {
			continue
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// SetCategories sets the category of the tenant's technologies that are
// still in category other.
func (r *AssetTechnologyBackfillRepository) SetCategories(ctx context.Context, tenantID shared.ID, rows []assettechapp.BackfillRow, cats []assettech.Category) error {
	if len(rows) == 0 || len(rows) != len(cats) {
		return nil
	}
	ids, keys, cs := make([]string, 0, len(rows)), make([]string, 0, len(rows)), make([]string, 0, len(rows))
	for i, row := range rows {
		if !cats[i].IsValid() {
			continue
		}
		ids = append(ids, row.AssetID.String())
		keys = append(keys, row.Key)
		cs = append(cs, string(cats[i]))
	}
	if _, err := r.db.ExecContext(ctx, `
		UPDATE asset_technologies t SET category = v.category, updated_at = now()
		  FROM unnest($2::uuid[], $3::text[], $4::text[]) AS v(asset_id, name_key, category)
		 WHERE t.tenant_id = $1 AND t.asset_id = v.asset_id AND t.name_key = v.name_key AND t.category = 'other'`,
		tenantID.String(), pq.Array(ids), pq.Array(keys), pq.Array(cs)); err != nil {
		return fmt.Errorf("set technology categories: %w", err)
	}
	return nil
}

// ScanTechnologyLinks returns the tenant's next component links whose
// source is a technology detection, after afterID in id order.
func (r *AssetTechnologyBackfillRepository) ScanTechnologyLinks(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]assettechapp.BackfillLink, error) {
	if afterID == "" {
		afterID = zeroUUID
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, p.name, v.raw, p.cpe_vendor IS NOT NULL
		  FROM asset_software s
		  JOIN software_products p ON p.id = s.product_id
		  JOIN software_versions v ON v.id = s.software_version_id
		 WHERE s.tenant_id = $1 AND s.source = 'technology' AND s.id > $2::uuid
		   AND NOT EXISTS (SELECT 1 FROM asset_software_edges e WHERE e.parent_id = s.id OR e.child_id = s.id)
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

// DeleteLinks deletes the tenant's technology links by id and records each
// deleted row in asset_technology_backfill_removed, in one statement. The
// statement repeats the backfill's rule (assettech.CleanVersion(version) is
// empty and the product has no CPE): a versioned or CPE-backed link is never
// deleted, whatever ids are passed. A link that is an end of a dependency
// edge is skipped too, so the edge cascade never removes anything else.
func (r *AssetTechnologyBackfillRepository) DeleteLinks(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	list := make([]string, 0, len(ids))
	for _, id := range ids {
		list = append(list, id.String())
	}
	res, err := r.db.ExecContext(ctx, `
		WITH d AS (
		    DELETE FROM asset_software s
		     USING software_products p, software_versions v
		     WHERE s.tenant_id = $1 AND s.source = 'technology' AND s.id = ANY($2::uuid[])
		       AND p.id = s.product_id AND v.id = s.software_version_id
		       AND p.cpe_vendor IS NULL
		       AND (v.raw ~ '^[[:space:]]*$' OR octet_length(btrim(v.raw)) > $3 OR v.raw ~ '[[:cntrl:]]')
		       AND NOT EXISTS (SELECT 1 FROM asset_software_edges e WHERE e.parent_id = s.id OR e.child_id = s.id)
		    RETURNING s.tenant_id, s.asset_id, s.id AS link_id, p.name AS product, v.raw AS version,
		              s.confidence, s.first_seen_at, s.last_seen_at
		)
		INSERT INTO asset_technology_backfill_removed
		       (tenant_id, asset_id, link_id, product, version, confidence, first_seen, last_seen, removed_at)
		SELECT tenant_id, asset_id, link_id, product, version, confidence, first_seen_at, last_seen_at, now()
		  FROM d`,
		tenantID.String(), pq.Array(list), assettech.MaxVersionLen)
	if err != nil {
		return 0, fmt.Errorf("delete technology links: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkBackfilled records that a tenant was backfilled at version.
func (r *AssetTechnologyBackfillRepository) MarkBackfilled(ctx context.Context, tenantID shared.ID, version int, enforced bool, stats assettechapp.BackfillStats) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_technology_backfill (tenant_id, version, technologies, classified, links_removed, links_reported, enforced, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (tenant_id) DO UPDATE SET
		       version = EXCLUDED.version, technologies = EXCLUDED.technologies,
		       classified = EXCLUDED.classified, links_removed = EXCLUDED.links_removed,
		       links_reported = EXCLUDED.links_reported, enforced = EXCLUDED.enforced,
		       completed_at = EXCLUDED.completed_at`,
		tenantID.String(), version, stats.Technologies, stats.Classified, stats.LinksRemoved, stats.LinksReported, enforced)
	if err != nil {
		return fmt.Errorf("mark technology backfill: %w", err)
	}
	return nil
}
