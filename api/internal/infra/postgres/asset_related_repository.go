package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// relatedEdgesCTE lists every edge of asset $2 in tenant $1 once, seen from
// that asset: the direction and the id of the asset at the other end.
const relatedEdgesCTE = `
	WITH edges AS (
		SELECT ar.id, ar.relationship_type, 'outgoing'::text AS direction,
		       ar.target_asset_id AS other_id, ar.discovery_method, ar.confidence,
		       ar.is_control_plane, ar.last_verified, ar.created_at
		FROM asset_relationships ar
		WHERE ar.tenant_id = $1 AND ar.source_asset_id = $2
		UNION ALL
		SELECT ar.id, ar.relationship_type, 'incoming'::text,
		       ar.source_asset_id, ar.discovery_method, ar.confidence,
		       ar.is_control_plane, ar.last_verified, ar.created_at
		FROM asset_relationships ar
		WHERE ar.tenant_id = $1 AND ar.target_asset_id = $2
	)`

// relatedCriticalityRank orders the related assets of a group most critical
// first, so the rows shown before "show all" are the ones that matter.
const relatedCriticalityRank = `CASE a.criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1
	WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`

const (
	relatedDefaultLimit = 5
	relatedMaxLimit     = 100
	relatedMaxOffset    = 100000
)

// RelatedAssets returns the edges of one asset grouped by (type, direction),
// each group with its total and its rows Offset..Offset+Limit, most critical
// related asset first. Every query is bound to the tenant; with a scope only
// edges whose other asset is in it are returned, and the rest are counted in
// HiddenCount (never filtered by type or search, so a search cannot probe the
// names of assets the caller may not see).
func (r *AssetRelationshipRepository) RelatedAssets(
	ctx context.Context,
	tenantID, assetID shared.ID,
	q asset.RelatedAssetsQuery,
) (*asset.RelatedAssets, error) {
	args := []any{tenantID.String(), assetID.String()}
	visible := sqlTrue
	if q.Scope != nil {
		cond, scopeArgs := dataScopeCondAt("e.other_id", q.Scope, len(args)+1)
		visible = cond
		args = append(args, scopeArgs...)
	}

	out := &asset.RelatedAssets{}

	// Hidden edges: a count only, over every edge of the asset.
	//nolint:gosec // G201: visible is built from fixed SQL and numbered placeholders
	hiddenQuery := relatedEdgesCTE + fmt.Sprintf(`
		SELECT COUNT(*) - COUNT(*) FILTER (WHERE %s) FROM edges e`, visible)
	if err := r.db.QueryRowContext(ctx, hiddenQuery, args...).Scan(&out.HiddenCount); err != nil {
		return nil, fmt.Errorf("count hidden related assets: %w", err)
	}

	where, filterArgs := relatedFilter(q, len(args)+1)
	args = append(args, filterArgs...)
	//nolint:gosec // G201: visible and where are built from fixed SQL and numbered placeholders
	base := fmt.Sprintf(`
		FROM edges e
		JOIN assets a ON a.id = e.other_id AND a.tenant_id = $1
		WHERE %s%s`, visible, where)

	totals := map[string]int64{}
	var order []string
	rows, err := r.db.QueryContext(ctx, relatedEdgesCTE+`
		SELECT e.relationship_type, e.direction, COUNT(*)`+base+`
		GROUP BY e.relationship_type, e.direction
		ORDER BY e.relationship_type, e.direction`, args...)
	if err != nil {
		return nil, fmt.Errorf("count related assets: %w", err)
	}
	for rows.Next() {
		var typ, dir string
		var n int64
		if err := rows.Scan(&typ, &dir, &n); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan related group: %w", err)
		}
		key := typ + "|" + dir
		totals[key] = n
		order = append(order, key)
		out.Total += n
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate related groups: %w", err)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = relatedDefaultLimit
	}
	limit = min(limit, relatedMaxLimit)
	offset := min(max(q.Offset, 0), relatedMaxOffset)
	n := len(args)
	args = append(args, offset, offset+limit)

	//nolint:gosec // G202: base is built from fixed SQL and numbered placeholders
	itemsQuery := relatedEdgesCTE + `
		, ranked AS (
			SELECT e.id, e.relationship_type, e.direction, a.id AS asset_id, a.name, a.asset_type,
			       COALESCE(a.sub_type, ''), COALESCE(a.status, ''), COALESCE(a.criticality, ''),
			       COALESCE(a.exposure, ''), a.last_seen, e.discovery_method, e.confidence,
			       e.is_control_plane, e.last_verified, e.created_at,
			       ROW_NUMBER() OVER (PARTITION BY e.relationship_type, e.direction
			                          ORDER BY ` + relatedCriticalityRank + `, a.name, e.id) AS rn` + base + `
		)
		SELECT * FROM ranked WHERE rn > $` + fmt.Sprint(n+1) + ` AND rn <= $` + fmt.Sprint(n+2) + `
		ORDER BY relationship_type, direction, rn`
	rows, err = r.db.QueryContext(ctx, itemsQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list related assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	items := map[string][]asset.RelatedAsset{}
	for rows.Next() {
		it, err := scanRelatedAsset(rows)
		if err != nil {
			return nil, err
		}
		key := it.Type.String() + "|" + it.Direction
		items[key] = append(items[key], it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate related assets: %w", err)
	}

	out.Groups = make([]asset.RelatedAssetGroup, 0, len(order))
	for _, key := range order {
		typ, dir, _ := strings.Cut(key, "|")
		g := asset.RelatedAssetGroup{Type: asset.RelationshipType(typ), Direction: dir, Total: totals[key], Items: items[key]}
		if g.Items == nil {
			g.Items = []asset.RelatedAsset{}
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}

// relatedFilter narrows the visible edges to one group and a name search.
func relatedFilter(q asset.RelatedAssetsQuery, first int) (string, []any) {
	where := ""
	var args []any
	if q.Type != "" {
		args = append(args, q.Type.String())
		where += fmt.Sprintf(" AND e.relationship_type = $%d", first+len(args)-1)
	}
	if q.Direction != "" {
		args = append(args, q.Direction)
		where += fmt.Sprintf(" AND e.direction = $%d", first+len(args)-1)
	}
	if q.Search != "" {
		args = append(args, wrapLikePattern(q.Search))
		where += fmt.Sprintf(" AND a.name ILIKE $%d", first+len(args)-1)
	}
	return where, args
}

func scanRelatedAsset(rows *sql.Rows) (asset.RelatedAsset, error) {
	var (
		it                         asset.RelatedAsset
		relID, otherID, typ, aType string
		assetLastSeen, verified    sql.NullTime
		createdAt                  time.Time
		rn                         int64
	)
	if err := rows.Scan(&relID, &typ, &it.Direction, &otherID, &it.AssetName, &aType,
		&it.AssetSubType, &it.AssetStatus, &it.Criticality, &it.Exposure, &assetLastSeen,
		&it.DiscoveryMethod, &it.Confidence, &it.IsControlPlane, &verified, &createdAt, &rn); err != nil {
		return it, fmt.Errorf("scan related asset: %w", err)
	}
	var err error
	if it.RelationshipID, err = shared.IDFromString(relID); err != nil {
		return it, fmt.Errorf("parse relationship id: %w", err)
	}
	if it.AssetID, err = shared.IDFromString(otherID); err != nil {
		return it, fmt.Errorf("parse asset id: %w", err)
	}
	it.Type = asset.RelationshipType(typ)
	it.AssetType = asset.AssetType(aType)
	it.CreatedAt = createdAt
	if assetLastSeen.Valid {
		t := assetLastSeen.Time
		it.AssetLastSeen = &t
	}
	if verified.Valid {
		t := verified.Time
		it.LastVerified = &t
	}
	return it, nil
}
