package postgres

// Discovery lineage (docs/architecture/easm.md, Discovery lineage): the
// ancestor chain of an asset, one parent per hop.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ asset.LineageReader = (*AssetRelationshipRepository)(nil)

// lineageQuery walks up from asset $2 of tenant $1, at most $3 hops. Each hop
// picks ONE parent of the current asset: its parent_id first, then the
// source of a hierarchy edge pointing at it (contains, exposes,
// serves_certificate, resolves_to, in that order, oldest first). Every table
// is bound to the tenant on every hop, a soft-deleted parent ends the chain,
// and an asset already on the path is never revisited (cycle guard). %s is
// the visibility predicate on a.id (TRUE for an unrestricted caller).
const lineageQuery = `
WITH RECURSIVE chain(id, depth, via, path) AS (
	SELECT a.id, 0, ''::text, ARRAY[a.id]
	FROM assets a
	WHERE a.tenant_id = $1 AND a.id = $2
	UNION ALL
	SELECT p.parent_id, c.depth + 1, p.via, c.path || p.parent_id
	FROM chain c
	CROSS JOIN LATERAL (
		SELECT x.parent_id, x.via
		FROM (
			SELECT ca.parent_id, 'parent'::text AS via, 0 AS pref, NULL::timestamptz AS created
			FROM assets ca
			WHERE ca.tenant_id = $1 AND ca.id = c.id AND ca.parent_id IS NOT NULL
			UNION ALL
			SELECT r.source_asset_id, r.relationship_type::text,
				CASE r.relationship_type
					WHEN 'contains' THEN 1 WHEN 'exposes' THEN 2
					WHEN 'serves_certificate' THEN 3 ELSE 4 END,
				r.created_at
			FROM asset_relationships r
			WHERE r.tenant_id = $1 AND r.target_asset_id = c.id
				AND r.relationship_type IN ('contains', 'exposes', 'serves_certificate', 'resolves_to')
		) x
		JOIN assets pa ON pa.tenant_id = $1 AND pa.id = x.parent_id AND pa.deleted_at IS NULL
		WHERE NOT (x.parent_id = ANY (c.path))
		ORDER BY x.pref, x.created NULLS FIRST, x.parent_id
		LIMIT 1
	) p
	WHERE c.depth < $3
)
SELECT c.depth, c.via, v.visible,
	CASE WHEN v.visible THEN a.id::text END,
	CASE WHEN v.visible THEN a.name END,
	CASE WHEN v.visible THEN a.asset_type END,
	CASE WHEN v.visible THEN a.discovery_source END,
	CASE WHEN v.visible THEN a.discovery_tool END,
	CASE WHEN v.visible THEN a.discovered_at END,
	CASE WHEN v.visible THEN a.first_seen END
FROM chain c
JOIN assets a ON a.tenant_id = $1 AND a.id = c.id
CROSS JOIN LATERAL (SELECT (c.depth = 0 OR %s) AS visible) v
ORDER BY c.depth`

// Lineage returns the ancestor chain of assetID, the asset first (depth 0),
// with at most maxDepth+1 ancestors so the caller can tell a truncated
// chain. With a non-nil scope an ancestor outside it comes back Hidden with
// no identifying field (the database never returns its name). The asset
// itself is returned as visible: the caller has already checked it.
func (r *AssetRelationshipRepository) Lineage(
	ctx context.Context, tenantID, assetID shared.ID, scope *shared.DataScope, maxDepth int,
) ([]asset.LineageNode, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
	args := []any{tenantID.String(), assetID.String(), maxDepth + 1}
	visible := sqlTrue
	if scope != nil {
		cond, scopeArgs := dataScopeCondAt("a.id", scope, len(args)+1)
		args = append(args, scopeArgs...)
		visible = "(" + cond + ")"
	}
	//nolint:gosec // G201: visible is built from fixed SQL and numbered placeholders
	q := fmt.Sprintf(lineageQuery, visible)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query asset lineage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []asset.LineageNode
	for rows.Next() {
		var (
			n                        asset.LineageNode
			visibleRow               bool
			id, name, typ, src, tool sql.NullString
			discovered, firstSeen    sql.NullTime
		)
		if err := rows.Scan(&n.Depth, &n.Via, &visibleRow, &id, &name, &typ, &src, &tool, &discovered, &firstSeen); err != nil {
			return nil, fmt.Errorf("scan asset lineage: %w", err)
		}
		n.Hidden = !visibleRow
		if visibleRow {
			if n.ID, err = shared.IDFromString(id.String); err != nil {
				return nil, fmt.Errorf("asset lineage id: %w", err)
			}
			n.Name, n.Type = name.String, asset.AssetType(typ.String)
			n.DiscoverySource, n.DiscoveryTool = src.String, tool.String
			n.DiscoveredAt, n.FirstSeen = utcTimePtr(discovered), utcTimePtr(firstSeen)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func utcTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.In(time.UTC)
	return &v
}
