package postgres

// The assets behind scan targets, for scan window selectors (RFC-067 §4.2).
// Tenant-scoped; deleted assets never match.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lib/pq"

	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanWindowAssetRepository matches targets to assets and lists the assets
// a selector selects.
type ScanWindowAssetRepository struct {
	db *DB
}

// NewScanWindowAssetRepository creates a ScanWindowAssetRepository.
func NewScanWindowAssetRepository(db *DB) *ScanWindowAssetRepository {
	return &ScanWindowAssetRepository{db: db}
}

var _ swdom.AssetMatcher = (*ScanWindowAssetRepository)(nil)

// maxMatchedAssets bounds one match (a wide CIDR over many IP assets).
const maxMatchedAssets = 20000

// assetAttrColumns are the selector attributes of the asset aliased a.
const assetAttrColumns = `a.id::text, a.name, a.asset_type, a.criticality, COALESCE(a.tags, '{}'),
	ARRAY(SELECT m.asset_group_id::text FROM asset_group_members m
	      JOIN asset_groups g ON g.id = m.asset_group_id AND g.tenant_id = a.tenant_id
	      WHERE m.asset_id = a.id),
	ARRAY(SELECT b.business_unit_id::text FROM business_unit_assets b
	      WHERE b.asset_id = a.id AND b.tenant_id = a.tenant_id)`

// MatchTargetAssets returns, per target, the tenant's assets it names: an
// asset named as the target, its lower-case form or its host (URL,
// host:port); and for a CIDR target every IP asset inside the range.
func (r *ScanWindowAssetRepository) MatchTargetAssets(ctx context.Context, tenantID shared.ID, targets []string) (map[string][]swdom.TargetAsset, error) {
	var formT, forms, cidrT, cidrs []string
	for _, t := range targets {
		for _, f := range scopedom.AuthorityForms(t) {
			formT, forms = append(formT, t), append(forms, f)
		}
		if p, err := netip.ParsePrefix(strings.TrimSpace(t)); err == nil && !p.IsSingleIP() {
			cidrT, cidrs = append(cidrT, t), append(cidrs, p.Masked().String())
		}
	}
	out := map[string][]swdom.TargetAsset{}
	if len(forms) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH f(target, form) AS (SELECT * FROM unnest($2::text[], $3::text[])),
		     c(target, cidr) AS (SELECT * FROM unnest($4::text[], $5::text[])),
		     hit AS (
			SELECT f.target, a.id FROM f
			JOIN assets a ON a.tenant_id = $1 AND a.name = f.form AND a.deleted_at IS NULL
			UNION
			SELECT c.target, a.id FROM c
			JOIN assets a ON a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_type = 'ip_address'
			 AND CASE WHEN pg_input_is_valid(a.name, 'inet') THEN a.name::inet <<= c.cidr::cidr ELSE false END
		     )
		SELECT hit.target, `+assetAttrColumns+`
		FROM hit JOIN assets a ON a.id = hit.id AND a.tenant_id = $1
		LIMIT $6`,
		tenantID.String(), pq.Array(formT), pq.Array(forms), pq.Array(cidrT), pq.Array(cidrs), maxMatchedAssets)
	if err != nil {
		return nil, fmt.Errorf("match target assets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		var a swdom.TargetAsset
		if err := rows.Scan(&target, &a.ID, &a.Name, &a.Type, &a.Criticality, pq.Array(&a.Tags),
			pq.Array(&a.GroupIDs), pq.Array(&a.BusinessUnitIDs)); err != nil {
			return nil, fmt.Errorf("match target assets: %w", err)
		}
		out[target] = append(out[target], a)
	}
	return out, rows.Err()
}

// MatchingAssets lists the tenant's assets that meet the asset dimensions of
// sel (tags, groups, types, criticality, business units), ordered by name,
// at most limit, with the total. Other dimensions are not considered.
func (r *ScanWindowAssetRepository) MatchingAssets(ctx context.Context, tenantID shared.ID, sel swdom.Selector, limit int) (int, []swdom.TargetAsset, error) {
	if !sel.UsesAssets() {
		return 0, nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var tags []string
	for _, t := range sel.Tags {
		tags = append(tags, strings.ToLower(t))
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+assetAttrColumns+`, count(*) OVER ()
		FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		  AND ($2::text[] IS NULL OR EXISTS (SELECT 1 FROM unnest(a.tags) t WHERE lower(t) = ANY($2::text[])))
		  AND ($3::uuid[] IS NULL OR EXISTS (
		        SELECT 1 FROM asset_group_members m JOIN asset_groups g ON g.id = m.asset_group_id AND g.tenant_id = $1
		        WHERE m.asset_id = a.id AND m.asset_group_id = ANY($3::uuid[])))
		  AND ($4::text[] IS NULL OR a.asset_type = ANY($4::text[]))
		  AND ($5::text[] IS NULL OR a.criticality = ANY($5::text[]))
		  AND ($6::uuid[] IS NULL OR EXISTS (
		        SELECT 1 FROM business_unit_assets b
		        WHERE b.asset_id = a.id AND b.tenant_id = $1 AND b.business_unit_id = ANY($6::uuid[])))
		ORDER BY a.name, a.id
		LIMIT $7`,
		tenantID.String(), nilArray(tags), nilArray(sel.AssetGroupIDs), nilArray(sel.AssetTypes),
		nilArray(sel.Criticalities), nilArray(sel.BusinessUnitIDs), limit)
	if err != nil {
		return 0, nil, fmt.Errorf("list matching assets: %w", err)
	}
	defer rows.Close()
	total := 0
	var out []swdom.TargetAsset
	for rows.Next() {
		var a swdom.TargetAsset
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Criticality, pq.Array(&a.Tags),
			pq.Array(&a.GroupIDs), pq.Array(&a.BusinessUnitIDs), &total); err != nil {
			return 0, nil, fmt.Errorf("list matching assets: %w", err)
		}
		out = append(out, a)
	}
	return total, out, rows.Err()
}

// AssetNames returns the names of the tenant's live assets among ids.
func (r *ScanWindowAssetRepository) AssetNames(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error) {
	out := map[shared.ID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text, name FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`,
		tenantID.String(), pq.Array(windowIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("read asset names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		if aid, err := shared.IDFromString(id); err == nil {
			out[aid] = name
		}
	}
	return out, rows.Err()
}

// nilArray is a text/uuid array argument, NULL when empty.
func nilArray(v []string) any {
	if len(v) == 0 {
		return nil
	}
	return pq.Array(v)
}
