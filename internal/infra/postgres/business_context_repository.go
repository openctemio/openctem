package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/api/internal/app/finding"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// BusinessContextLookupRepo resolves per-asset business-unit and
// business-service criticality for business-aligned prioritization. It
// implements finding.BusinessContextLookup with three batch, tenant-scoped
// queries (BU membership, business-service membership, and control-plane
// propagation) and reduces each to the MAX criticality per asset in Go — no
// per-asset query.
type BusinessContextLookupRepo struct {
	db *sql.DB
}

// NewBusinessContextLookupRepo creates a new lookup adapter.
func NewBusinessContextLookupRepo(db *sql.DB) *BusinessContextLookupRepo {
	return &BusinessContextLookupRepo{db: db}
}

var _ finding.BusinessContextLookup = (*BusinessContextLookupRepo)(nil)

// GetForAssets returns, for each asset, the MAX business-unit criticality and
// the MAX business-service criticality (with the source name), keyed by asset
// ID. Assets that belong to no BU and power no service are absent from the map.
// Both queries are tenant-scoped.
func (r *BusinessContextLookupRepo) GetForAssets(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
) (map[shared.ID]finding.AssetBusinessContext, error) {
	result := make(map[shared.ID]finding.AssetBusinessContext)
	if len(assetIDs) == 0 {
		return result, nil
	}

	idStrings := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		idStrings[i] = id.String()
	}

	// Pass 1: business-unit criticality WITH parent-hierarchy inheritance. An
	// asset may belong to several BUs (reduce to the most critical), and a BU
	// inherits the MAX criticality along its parent_id chain — a child BU under a
	// Critical parent is at least as critical. Only ever raises (floor); a flat /
	// parentless hierarchy reduces to the BU's own criticality (back-compat).
	if err := r.foldBusinessUnitCriticality(ctx, tenantID, idStrings, result); err != nil {
		return nil, fmt.Errorf("business unit criticality lookup: %w", err)
	}

	// Pass 2: business-service criticality (an asset may power several services;
	// reduce to the most critical).
	svcQuery := `
		SELECT bsa.asset_id, bs.criticality, bs.name
		FROM business_service_assets bsa
		JOIN business_services bs
		  ON bs.id = bsa.service_id AND bs.tenant_id = bsa.tenant_id
		WHERE bsa.tenant_id = $1
		  AND bsa.asset_id = ANY($2)
	`
	if err := r.reduceMaxCriticality(ctx, svcQuery, tenantID, idStrings, result, applyService); err != nil {
		return nil, fmt.Errorf("business service criticality lookup: %w", err)
	}

	// Pass 3: control-plane propagation, BOUNDED MULTI-HOP. An asset marked as the
	// control plane of another (is_control_plane edge) is itself as critical as
	// what it serves — compromising it pulls in the served asset. Per the #467 data
	// model the control-plane asset is the TARGET of the edge and the served asset
	// is the SOURCE (e.g. service --depends_on--> IdP, is_control_plane=true: the
	// IdP is the control plane). Propagation is transitive: the IdP that administers
	// the secrets store that fronts a crown jewel is itself critical, so we walk up
	// to maxControlPlaneDepth hops with a cycle guard. Only ever raises (floor).
	// Direction note: per-relationship-type normalization (manages/monitors put the
	// control plane on the source) is a follow-up; today we key off the
	// depends_on-style target endpoint.
	if err := r.foldControlPlaneMultiHop(ctx, tenantID, idStrings, result); err != nil {
		return nil, fmt.Errorf("control-plane criticality lookup: %w", err)
	}

	return result, nil
}

// criticalityApplier folds one (criticality, name) membership row into an asset's
// business context, updating the relevant leg when the row is more critical than
// what is already recorded. Each pass (BU, service, control-plane) supplies its
// own applier so reduceMaxCriticality stays generic.
type criticalityApplier func(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string)

func applyBU(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string) {
	if crit.Score() > bctx.BusinessUnitCriticality.Score() {
		bctx.BusinessUnitCriticality = crit
		bctx.BusinessUnitName = name
	}
}

func applyService(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string) {
	if crit.Score() > bctx.BusinessServiceCriticality.Score() {
		bctx.BusinessServiceCriticality = crit
		bctx.BusinessServiceName = name
	}
}

func applyControlPlane(bctx *finding.AssetBusinessContext, crit asset.Criticality, name string) {
	if crit.Score() > bctx.ControlPlaneServesCriticality.Score() {
		bctx.ControlPlaneServesCriticality = crit
		bctx.ControlPlaneServesName = name
	}
}

// reduceMaxCriticality runs a membership query returning (asset_id, criticality,
// name) rows and folds the MAX criticality per asset into result via the supplied
// applier (which decides WHICH leg — BU, service, or control-plane — the row
// contributes to).
func (r *BusinessContextLookupRepo) reduceMaxCriticality(
	ctx context.Context,
	query string,
	tenantID shared.ID,
	idStrings []string,
	result map[shared.ID]finding.AssetBusinessContext,
	apply criticalityApplier,
) error {
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrings))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var aidStr, critStr, name string
		if err := rows.Scan(&aidStr, &critStr, &name); err != nil {
			continue
		}
		aid, err := shared.IDFromString(aidStr)
		if err != nil {
			continue
		}
		crit := asset.Criticality(critStr)

		bctx := result[aid]
		apply(&bctx, crit, name)
		result[aid] = bctx
	}
	return rows.Err()
}

// maxBUHierarchyDepth bounds the parent-chain walk for business-unit criticality
// inheritance. Organizational hierarchies are shallow; the cap (with the visited
// cycle guard) makes a malformed/cyclic parent chain terminate cheaply.
const maxBUHierarchyDepth = 16

// buNode is one business unit in the tenant hierarchy: its own criticality, name,
// and parent link ("" when it is a root).
type buNode struct {
	parentID string
	crit     asset.Criticality
	name     string
}

// buResolved is a BU's inherited (effective) criticality and the name of the BU
// in its ancestor chain that supplied it.
type buResolved struct {
	crit asset.Criticality
	name string
}

// foldBusinessUnitCriticality folds each asset's business-unit criticality into
// result, inheriting the MAX criticality along the BU's parent chain. It issues
// two batch, tenant-scoped queries (the tenant's BU hierarchy and asset→BU
// membership) and resolves inheritance in Go — no per-asset query. Only ever
// raises (floor); a flat/parentless hierarchy reduces to the BU's own criticality.
func (r *BusinessContextLookupRepo) foldBusinessUnitCriticality(
	ctx context.Context,
	tenantID shared.ID,
	assetIDStrings []string,
	result map[shared.ID]finding.AssetBusinessContext,
) error {
	nodes, err := r.loadBUHierarchy(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return nil
	}

	// Memoize resolved (inherited) criticality per BU across all memberships so a
	// BU shared by many assets is walked once.
	resolvedCache := make(map[string]buResolved, len(nodes))
	resolve := func(id string) buResolved {
		if v, ok := resolvedCache[id]; ok {
			return v
		}
		crit, name := resolveBUCriticality(id, nodes, maxBUHierarchyDepth)
		v := buResolved{crit: crit, name: name}
		resolvedCache[id] = v
		return v
	}

	const membershipQuery = `
		SELECT bua.asset_id, bua.business_unit_id
		FROM business_unit_assets bua
		WHERE bua.tenant_id = $1
		  AND bua.asset_id = ANY($2)
	`
	rows, err := r.db.QueryContext(ctx, membershipQuery, tenantID.String(), pq.Array(assetIDStrings))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var aidStr, buIDStr string
		if err := rows.Scan(&aidStr, &buIDStr); err != nil {
			continue
		}
		aid, err := shared.IDFromString(aidStr)
		if err != nil {
			continue
		}
		rv := resolve(buIDStr)
		if rv.crit == "" {
			continue
		}
		bctx := result[aid]
		applyBU(&bctx, rv.crit, rv.name)
		result[aid] = bctx
	}
	return rows.Err()
}

// loadBUHierarchy loads every business unit for the tenant as a node map keyed by
// BU id. Tenant-scoped. BU counts are small (organizational units), so one query
// suffices and inheritance is resolved in memory rather than with a per-BU query.
func (r *BusinessContextLookupRepo) loadBUHierarchy(ctx context.Context, tenantID shared.ID) (map[string]buNode, error) {
	const q = `
		SELECT id, COALESCE(parent_id::text, ''), criticality, name
		FROM business_units
		WHERE tenant_id = $1
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	nodes := make(map[string]buNode)
	for rows.Next() {
		var id, parent, crit, name string
		if err := rows.Scan(&id, &parent, &crit, &name); err != nil {
			continue
		}
		nodes[id] = buNode{parentID: parent, crit: asset.Criticality(crit), name: name}
	}
	return nodes, rows.Err()
}

// maxControlPlaneDepth bounds the multi-hop control-plane walk: a control plane of
// a control plane of a crown jewel still inherits (IdP → secrets store → crown
// jewel), but the cap plus cycle guard stop an adversarial/cyclic graph from
// blowing up.
const maxControlPlaneDepth = 3

// foldControlPlaneMultiHop folds control-plane propagation into result across up
// to maxControlPlaneDepth hops. An asset that is the control plane of a critical
// asset — directly OR transitively (control-plane-of-a-control-plane) — inherits
// that criticality. It gathers the reachable control-plane subgraph with at most
// maxControlPlaneDepth batched, tenant-scoped queries (never per-asset) and walks
// it in Go with a visited cycle guard. Only ever raises (floor).
func (r *BusinessContextLookupRepo) foldControlPlaneMultiHop(
	ctx context.Context,
	tenantID shared.ID,
	originIDStrings []string,
	result map[shared.ID]finding.AssetBusinessContext,
) error {
	edges := make(map[string][]string)         // control-plane id -> served (source) ids
	crit := make(map[string]asset.Criticality) // served id -> own criticality
	names := make(map[string]string)           // served id -> name
	expanded := make(map[string]bool)          // control-plane ids already queried

	// BFS over inbound is_control_plane edges: one batched query per hop, bounded
	// by maxControlPlaneDepth so a cyclic/deep graph cannot fan out unbounded.
	frontier := dedupStrings(originIDStrings)
	for depth := 0; depth < maxControlPlaneDepth && len(frontier) > 0; depth++ {
		toFetch := make([]string, 0, len(frontier))
		for _, id := range frontier {
			if !expanded[id] {
				expanded[id] = true
				toFetch = append(toFetch, id)
			}
		}
		if len(toFetch) == 0 {
			break
		}
		next, err := r.fetchControlPlaneEdges(ctx, tenantID, toFetch, edges, crit, names)
		if err != nil {
			return err
		}
		frontier = next
	}

	for _, originStr := range originIDStrings {
		oid, err := shared.IDFromString(originStr)
		if err != nil {
			continue
		}
		c, name := walkControlPlane(originStr, edges, crit, names, maxControlPlaneDepth)
		if c == "" {
			continue
		}
		bctx := result[oid]
		applyControlPlane(&bctx, c, name)
		result[oid] = bctx
	}
	return nil
}

// fetchControlPlaneEdges loads the inbound is_control_plane edges whose target is
// in `targets`, recording each edge (control-plane target -> served source) plus
// the served source's own criticality/name. Returns the newly-seen served ids
// (the next BFS frontier). Tenant-scoped.
func (r *BusinessContextLookupRepo) fetchControlPlaneEdges(
	ctx context.Context,
	tenantID shared.ID,
	targets []string,
	edges map[string][]string,
	crit map[string]asset.Criticality,
	names map[string]string,
) ([]string, error) {
	const q = `
		SELECT ar.target_asset_id, ar.source_asset_id, sa.criticality, sa.name
		FROM asset_relationships ar
		JOIN assets sa
		  ON sa.id = ar.source_asset_id AND sa.tenant_id = ar.tenant_id
		WHERE ar.tenant_id = $1
		  AND ar.is_control_plane = TRUE
		  AND ar.target_asset_id = ANY($2)
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), pq.Array(targets))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var next []string
	for rows.Next() {
		var targetID, sourceID, critStr, name string
		if err := rows.Scan(&targetID, &sourceID, &critStr, &name); err != nil {
			continue
		}
		edges[targetID] = append(edges[targetID], sourceID)
		if _, seen := crit[sourceID]; !seen {
			next = append(next, sourceID)
		}
		crit[sourceID] = asset.Criticality(critStr)
		names[sourceID] = name
	}
	return next, rows.Err()
}

// dedupStrings returns the input with duplicates removed, order-preserving.
func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
