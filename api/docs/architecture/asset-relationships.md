# Asset relationships: graph reads

How the platform reads the relationship graph between assets for people and
tools. The edge model (one row per `(tenant, source, target, type)` in
`asset_relationships`, one stored direction per type, the vocabulary in
`configs/relationship-types.yaml`) is described in
[asset-inventory-v2.md](asset-inventory-v2.md#related-assets); the design is
[RFC-148](../rfcs/RFC-148-asset-neighborhood.md).

Three reads, one engine:

| Read | Endpoint | Answers |
|---|---|---|
| Related groups | `GET /api/v1/assets/{id}/relationships/groups` | every edge of one asset, grouped by type and direction, paged per group |
| Lineage | `GET /api/v1/assets/{id}/lineage` | where the asset comes from: one parent per hop up to the root ([easm.md](easm.md#4o-discovery-lineage-built)) |
| Neighborhood | `GET /api/v1/assets/{id}/neighborhood` | the assets up to three hops around the asset, both directions, with its lineage |

Each read injects the tenant from the principal and the caller's data scope
in the database, and each is bounded (depth, rows, statement time). The
reader is `AssetRelationshipRepository` (`assetdom.GraphReader`: lineage and
neighborhood); nothing else walks the graph per request.

## Neighborhood

`GET /api/v1/assets/{id}/neighborhood` (`assets:read`, relationships module):

| Parameter | Default | Bound |
|---|---|---|
| `depth` | 2 | 1 to 3 (higher is clamped) |
| `direction` | `both` | `both`, `out` (only what each asset points at), `in` |
| `types` | all | asset types, comma separated, at most 32 |
| `relations` | all | relationship types, comma separated, at most 32 |
| `limit` | 150 | most assets drawn, at most 300 (higher is clamped) |

The walk is breadth first, one statement per hop for the whole frontier
(`neighborhoodHopQuery`), so a depth-3 answer is at most three statements
plus the lineage. For each frontier asset the statement reads its edges in both
directions through the unique index `(tenant_id, source_asset_id, ...)` and
`idx_asset_rel_target (tenant_id, target_asset_id)`, joins the asset at the
other end on `(tenant_id, id)`, skips soft-deleted assets and self edges, and
decides per edge:

- **visible**: the other asset is in the caller's scope (`filterspec.ScopeSQL`,
  so assets hidden from the caller, such as private program assets, count as
  outside it);
- **wanted**: visible and passing `direction`, `relations` and `types` (an
  asset already in the answer passes `types`, so the edge to it is drawn);
- **cluster**: more than 8 new wanted assets in one group (one anchor, one
  relationship type, one direction) come back as one cluster with the count
  per asset type, most critical first otherwise.

The service (`AssetRelationshipService.Neighborhood`) keeps a visited set:
an asset is walked once, an edge to an asset already in the answer is drawn
but not walked again, so cycles end the walk. When the node cap is reached the
rest of the hop is counted into clusters on its anchor and `truncated` is set.
The lineage (the same reader as `GET /lineage`) is read first and its visible
nodes join the answer before the walk, so they are never clustered away and
are always drawn, even at depth 1; they do not count toward the cap.

Answer: `nodes` (the asset first; `distance` in hops, absent for a lineage
ancestor beyond the depth; `expanded` when its own edges were read;
`hidden_neighbors`), `edges` (source to target as stored), `clusters` (`id`,
`anchor`, `type`, `direction` from the anchor, `count`, `by_type`), `lineage`
(the `GET /lineage` shape), `truncated`, `hidden_count`. A cluster is expanded
with the related groups endpoint (`?type=&direction=&offset=&limit=`), which
pages the same group; a node is expanded with a depth-1 neighborhood of it.

### Security

- Tenant: from the principal. Every table of every hop is bound to the tenant
  (`asset_relationships.tenant_id` and `assets.tenant_id`), so an edge pointing
  at another tenant's asset is never followed, even if one were stored (the
  composite foreign keys already refuse it), and two tenants holding the same
  address name never meet.
- The asset itself: route guard and service check; another tenant's asset or
  one outside the caller's scope answers 404.
- **Out-of-scope neighbors are counted, never returned or walked through.**
  The neighborhood follows the related-groups rule rather than the lineage's
  redacted stubs: a redacted node in the middle of a walk would show the
  shape of the graph beyond the caller's scope (how many assets hang off a
  hidden one, and through which hidden asset two visible ones connect). A
  visible asset reachable only through a hidden one is therefore not shown;
  the visible node carries `hidden_neighbors`. The count is taken over all
  of the anchor's edges and ignores `types`, `relations` and `direction`, so
  a filter cannot tell what a hidden asset is or how it is related. Lineage
  hops outside the scope stay hidden nodes with no id, name or type, as on
  `GET /lineage`.
- No identifier beyond what the asset APIs already return: asset ids, names,
  types, criticality, exposure, status. Edges carry no relationship id;
  cluster ids are derived from the anchor id, type and direction.
- Cost: depth and node caps above, at most three hop statements per call,
  each in a read-only transaction with a 3 s statement timeout, and a
  per-user rate limit (2 per second, burst 30) on the route.

Tests: `internal/infra/http/routes/asset_neighborhood_db_test.go` (two-hop
estate with lineage and cluster, filters, depth and cap bounds, cycles, data
scope including filter probing, cross-tenant shared name and corrupted
cross-tenant edges), `internal/app/asset/neighborhood_test.go` (bounds,
walk, cap, cycles).

### Measured cost

Scratch Postgres 17, 20 tenants of 50 000 assets (1 000 000 assets, 3 229 917
edges, 1.9 GB), warm cache, one hop statement:

| Hop | Execution |
|---|---|
| one address, hop 1 | 0.27 ms |
| one name, hop 1 | 0.24 ms |
| frontier of 12 (a hop 2), 95 edges | 0.74 ms |
| name, scoped caller (5 000 scope rows) | 3.6 ms |
| hub address with 30 000 incoming edges | 182 ms |
| the same hub, scoped caller | 191 ms |

Both directions use an index (`uq_asset_relationship`, `idx_asset_rel_target`);
no new index is needed. A hub's cost is the join and sort of its edges; the
cluster keeps the answer small whatever the hub's size.

## Web

The asset's Relationships tab has two views: the grouped list (the complete,
accessible view) and the graph. The graph reads the neighborhood at depth 2
(1, 2 or 3 to choose) and draws it on the shared flow canvas
(`components/flow`): columns from the asset outwards (sources left, targets
right, so the lineage reads from the root on the left), the lineage edges
highlighted with their verbs, clusters as counted nodes ("10 assets", the
relationship as the detail), hidden lineage hops as dashed "Hidden asset"
nodes, a legend by asset type, and a breadcrumb of the lineage above the
canvas. Selecting a node (click, or arrow keys then Enter) opens a panel to
open the asset, show its related assets (a depth-1 neighborhood merged into
the graph) or draw a cluster's members 50 at a time.

**Full screen** (the shared `FlowFullscreen`, also on the attack-path
canvas): the canvas's "Full screen" button or `f` opens the same view in a
full-viewport dialog (a full-screen sheet on a phone) with the hops selector,
legend, lineage trail, zoom and fit controls and the node panel; the page
state (hops, expansions, selection) carries over and the graph fits the
screen on open. Escape, the close button or `f` again leave it.
