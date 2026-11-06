package postgres

// Asset neighborhood (docs/architecture/asset-relationships.md,
// "Neighborhood"): one hop of the walk around an asset, read for a whole
// frontier at once.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ asset.NeighborhoodReader = (*AssetRelationshipRepository)(nil)

// neighborhoodTimeout bounds each hop's statement: a hop over a hub of tens
// of thousands of edges takes tens of milliseconds, so a hop that runs for
// seconds is stopped instead of holding a connection.
const neighborhoodTimeout = 3 * time.Second

// Row kinds of neighborhoodHopQuery (its first column).
const (
	nbRowEdge    = "edge"
	nbRowCluster = "cluster"
	nbRowHidden  = "hidden"
)

// neighborhoodHopQuery reads every edge of the frontier assets ($2) of
// tenant $1, both directions, through the unique index (tenant, source, ...)
// and idx_asset_rel_target (tenant, target). Each table is bound to the
// tenant, soft-deleted assets are skipped and self edges ignored. For each
// edge it decides, in the database:
//   - visible: the other asset is in the caller's scope (%s, TRUE for an
//     unrestricted caller);
//   - wanted: the edge passes the direction ($4), relationship ($5) and asset
//     type ($6) filters (an asset already in the answer, $3, passes the type
//     filter so the edge to it is drawn);
//   - per group (anchor, relationship type, direction): how many new wanted
//     visible assets it has.
//
// It returns three kinds of rows: 'edge' for a wanted visible edge whose
// asset is known or whose group has at most $7 new assets (most critical
// first), 'cluster' with the count per asset type of a bigger group, and
// 'hidden' with the number of distinct out-of-scope assets per anchor. The
// hidden count ignores every filter, so a filter cannot tell what an
// out-of-scope asset is or how it is related.
const neighborhoodHopQuery = `
WITH frontier AS (
	SELECT DISTINCT unnest($2::uuid[]) AS id
),
e AS (
	SELECT r.source_asset_id AS anchor, r.target_asset_id AS other,
		r.relationship_type::text AS rtype, 'outgoing'::text AS dir
	FROM frontier f
	JOIN asset_relationships r ON r.tenant_id = $1 AND r.source_asset_id = f.id
	UNION ALL
	SELECT r.target_asset_id, r.source_asset_id, r.relationship_type::text, 'incoming'::text
	FROM frontier f
	JOIN asset_relationships r ON r.tenant_id = $1 AND r.target_asset_id = f.id
),
j AS (
	SELECT e.anchor, e.other, e.rtype, e.dir,
		a.name, a.asset_type::text AS asset_type, COALESCE(a.sub_type, '') AS sub_type,
		COALESCE(a.status, '') AS status, COALESCE(a.criticality, '') AS criticality,
		COALESCE(a.exposure, '') AS exposure,
		(%s) AS visible,
		e.other = ANY ($3::uuid[]) AS known
	FROM e
	JOIN assets a ON a.tenant_id = $1 AND a.id = e.other AND a.deleted_at IS NULL
	WHERE e.other <> e.anchor
),
w AS (
	SELECT j.*,
		j.visible
		AND ($4 = 'both' OR (j.dir = 'outgoing' AND $4 = 'out') OR (j.dir = 'incoming' AND $4 = 'in'))
		AND (cardinality($5::text[]) = 0 OR j.rtype = ANY ($5::text[]))
		AND (j.known OR cardinality($6::text[]) = 0 OR j.asset_type = ANY ($6::text[])) AS wanted
	FROM j
),
g AS MATERIALIZED (
	SELECT w.*,
		COUNT(*) FILTER (WHERE w.wanted AND NOT w.known) OVER (PARTITION BY w.anchor, w.rtype, w.dir) AS grp_new,
		ROW_NUMBER() OVER (PARTITION BY w.anchor, w.rtype, w.dir
			ORDER BY CASE w.criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1
				WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, w.name, w.other) AS rn
	FROM w
)
SELECT 'edge' AS kind, anchor, other, rtype, dir, known, name, asset_type, sub_type, status,
	criticality, exposure, 1::bigint AS n, rn
FROM g WHERE wanted AND (known OR grp_new <= $7)
UNION ALL
SELECT 'cluster', anchor, NULL, rtype, dir, FALSE, NULL, asset_type, NULL, NULL, NULL, NULL, COUNT(*), 0
FROM g WHERE wanted AND NOT known AND grp_new > $7
GROUP BY anchor, rtype, dir, asset_type
UNION ALL
SELECT 'hidden', anchor, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, NULL, NULL, NULL, COUNT(DISTINCT other), 0
FROM g WHERE NOT visible
GROUP BY anchor
ORDER BY 1, 2, 4, 5, 14, 8`

// NeighborhoodHop reads one hop of a neighborhood walk (see
// neighborhoodHopQuery) in a read-only transaction with its own statement
// timeout.
func (r *AssetRelationshipRepository) NeighborhoodHop(
	ctx context.Context, tenantID shared.ID, q asset.NeighborhoodHopQuery,
) (*asset.NeighborhoodHop, error) {
	out := &asset.NeighborhoodHop{HiddenByAnchor: map[shared.ID]int{}}
	if len(q.Frontier) == 0 {
		return out, nil
	}
	rels := make([]string, 0, len(q.Relations))
	for _, t := range q.Relations {
		rels = append(rels, string(t))
	}
	types := make([]string, 0, len(q.Types))
	for _, t := range q.Types {
		types = append(types, string(t))
	}
	direction := q.Direction
	if direction == "" {
		direction = asset.NeighborhoodBoth
	}
	clusterAt := q.ClusterAt
	if clusterAt <= 0 {
		clusterAt = asset.NeighborhoodClusterAt
	}
	args := []any{tenantID.String(), pq.Array(neighborhoodIDs(q.Frontier)), pq.Array(neighborhoodIDs(q.Known)),
		direction, pq.Array(rels), pq.Array(types), clusterAt}
	visible := sqlTrue
	if q.Scope != nil {
		cond, scopeArgs := dataScopeCondAt("e.other", q.Scope, len(args)+1)
		args = append(args, scopeArgs...)
		visible = cond
	}
	//nolint:gosec // G201: visible is built from fixed SQL and numbered placeholders
	query := fmt.Sprintf(neighborhoodHopQuery, visible)

	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin neighborhood read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, neighborhoodTimeout); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query asset neighborhood: %w", err)
	}
	defer func() { _ = rows.Close() }()

	clusters := map[string]int{}
	for rows.Next() {
		var (
			kind, anchor                                    string
			other, rtype, dir, name, typ, sub, st, crit, ex sql.NullString
			known                                           bool
			n, rn                                           int64
		)
		if err := rows.Scan(&kind, &anchor, &other, &rtype, &dir, &known, &name, &typ, &sub, &st, &crit, &ex, &n, &rn); err != nil {
			return nil, fmt.Errorf("scan asset neighborhood: %w", err)
		}
		anchorID, err := shared.IDFromString(anchor)
		if err != nil {
			return nil, fmt.Errorf("neighborhood anchor id: %w", err)
		}
		switch kind {
		case nbRowEdge:
			otherID, err := shared.IDFromString(other.String)
			if err != nil {
				return nil, fmt.Errorf("neighborhood asset id: %w", err)
			}
			out.Edges = append(out.Edges, asset.NeighborhoodEdge{
				Anchor: anchorID, Type: asset.RelationshipType(rtype.String), Direction: dir.String, Known: known,
				Other: asset.NeighborhoodNode{
					ID: otherID, Name: name.String, Type: asset.AssetType(typ.String), SubType: sub.String,
					Status: st.String, Criticality: crit.String, Exposure: ex.String,
				},
			})
		case nbRowCluster:
			key := anchor + "|" + rtype.String + "|" + dir.String
			i, ok := clusters[key]
			if !ok {
				i = len(out.Clusters)
				clusters[key] = i
				out.Clusters = append(out.Clusters, asset.NeighborhoodCluster{
					Anchor: anchorID, Type: asset.RelationshipType(rtype.String), Direction: dir.String,
					ByType: map[asset.AssetType]int{},
				})
			}
			out.Clusters[i].ByType[asset.AssetType(typ.String)] += int(n)
		case nbRowHidden:
			out.HiddenByAnchor[anchorID] = int(n)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset neighborhood: %w", err)
	}
	return out, nil
}

func neighborhoodIDs(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
