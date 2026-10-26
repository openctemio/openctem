# Attack paths

How the platform answers "which assets can the internet reach, and through what".
Three read endpoints share one in-memory graph built from the tenant's assets and
relationships on each computation:

```
GET /api/v1/attack-surface/attack-paths       (assets:read, module attack_surface)  ranked assets
GET /api/v1/attack-surface/exposure-chains    (assets:read, module attack_surface)  shortest chain per dangerous asset
GET /api/v1/attack-surface/attack-paths/{id}  (assets:read, module attack_surface)  routes to one asset, step weights, choke points
```

Key code: `api/internal/app/attack/` (`path_scoring.go`, `exposure_chains.go`,
`path_detail.go`, `scoped.go`), the priority oracle in `api/cmd/server/reachability_oracle.go`, the
threat-model consumer in `api/internal/app/threatmodel/service.go`.

## Graph

- Nodes: every non-deleted asset of the tenant. Entry points are assets with
  exposure `public`.
- Edges: tenant relationships. Only the movement types listed in
  `attackPathRelationshipTypes` are walked, source to target.
- Edges whose source or target is not a live node (deleted asset) are skipped.

## Security controls

`protected_by` and `monitors` are not walked; they mark an asset as protected.
The direction follows `api/configs/relationship-types.yaml`: for `A protected_by B`
(a website protected by a WAF) the protected asset is the source `A`; for
`A monitors B` (a SIEM watching a host) it is the target `B`.

## Full result, one cache

The exposure-chain computation returns every chain. The result is cached per
tenant for 5 minutes (`chain_cache.go`) with concurrent callers sharing one
computation under a 30 second deadline. The cache is keyed by tenant id and holds
the unscoped result; each reader gets its own copy of the chain list. The
HTTP endpoint, the MCP tool, the priority oracle and threat-model generation all
read the same cache; only the HTTP and MCP responses apply a row cap, after the
caller's data scope.

## Data scope

Both reads are narrowed to the caller's data scope after the whole-graph
computation, and the scope is applied before any row cap:

- Attack-path scores: the ranked list of every asset is narrowed to the caller's
  assets, then the top 50 are taken. A member whose assets rank below 50
  tenant-wide still sees them. `reachable_from` keeps counting every entry point,
  in or out of scope (a count, no identity).
- Exposure chains: a chain is shown when its target is in scope; chains are then
  ranked and capped at 100. A step on the way that is out of scope (including an
  out-of-scope entry point) is returned as `{"hidden": true}` with no id, name,
  type or exposure, so an owner learns that their asset is reachable without
  learning what lies in between. The hop count stays visible. The summary
  counts the chains the caller may see; its entry-point figure is a count of
  distinct entry points behind those chains.
- Callers with no restriction (owners, administrators, full-data roles) get the
  unfiltered result. The MCP exposure-chains tool follows the same rules.

## Linear computation

Exposure chains are built in one breadth-first pass that starts from every public
entry point at once, so each asset is visited a single time: O(assets + edges).
Every asset with an open KEV or critical finding gets the shortest path from its
nearest entry point. Edges whose source or target is not a live asset are
ignored, so a path never runs through a deleted asset.

The response no longer carries `reachable_from_entry_points`: counting entry
points per target is what made the earlier search quadratic, and the figure
mostly measured the size of the external footprint. The chain shows its own
entry point.

Measured with `go test ./internal/app/attack -bench BuildExposureChains_50k`
(50,000 assets, 100,000 edges, 10% public): about 33 ms per computation. The
earlier per-entry-point search needed 156 s on the same shape of graph. A parity
test compares lengths and reachability with the earlier algorithm on random
graphs.

## Routes to one asset

`GET /attack-surface/attack-paths/{id}` answers "how can the internet reach this
asset, how likely is each route, and which fix cuts the most routes".

- **Routes.** Every simple route from a public entry point to the asset over the
  movement relationships, up to the shortest length plus 2 edges (never more
  than 8). A route never passes through a second public asset: that is the
  shorter route from that asset. The enumeration stops after 200 routes or
  50,000 steps (`capped: true`); the response returns the 12 shortest, most
  likely routes and `total_paths`.
- **Step weight.** Each asset on a route carries the weight of the step onto
  it: the largest of the lead finding's EPSS score, 0.9 when the finding is in
  KEV, and a severity floor (critical 0.5, high 0.3, medium 0.1, low 0.05). The
  lead finding is the open finding with the largest weight; informational
  findings and low-confidence version matches are never a lead. An asset with
  no lead finding is an `assumed` step at weight 1: the relationship alone is
  taken to allow it. The response names the basis (`epss`, `kev`, `severity`,
  `assumed`) of every weight, so nothing is hidden.
- **Route likelihood** is the product of the step weights, entry point and
  target included. Routes rank by length, then likelihood.
- **Choke points** are the assets with a lead finding (the target excluded) on
  the shown routes, ranked by the number of routes through them, then weight.
  Fixing an asset's open findings removes its step, which cuts those routes.
- **Counts equal lists.** `open_findings` on a node is the asset's count under
  the findings list's Open lens, so the "View N findings" link
  (`/findings?asset_id=…&informational=true`) opens exactly that many rows
  (`tests/integration/attack_path_findings_test.go`).
- **Data scope.** The target must be in the caller's scope, otherwise 404, the
  same answer as an asset of another tenant or an unknown id. The routes are
  those of the whole graph; a step outside the scope is returned as
  `{"hidden": true}` with only its key and role. Its findings are never read,
  it is never a choke point, the relationship type of an edge touching it is
  left out, and the likelihood of a route through it is withheld. Node keys
  (`n0`, `n1`, …) are local to one response.
- The computation is per request (no cache) behind the heavy-read limiter: it
  loads the tenant's nodes and edges once and runs one reverse breadth-first
  pass plus a bounded depth-first enumeration.

## Scoring cache and finding counts

Attack-path scores (`GET /attack-surface/attack-paths`) use the same kind of
cache as the chains: one result per tenant for 5 minutes, concurrent callers
share one computation, which runs under a 30 second deadline. Data-scope
narrowing works on the caller's copy.

- A relationship whose source or target is not a live asset (a deleted asset) is
  ignored: it does not bridge a path and does not mark an asset as protected.
- `finding_count` on a scored asset counts open findings only (the open status
  set), so resolved, closed and dispositioned findings do not raise the score.
  Branch-only findings are still left out.

## Web pages

- `/attack-paths` is the view of one target: a flow canvas (the graph kit in
  `web/src/components/flow/`: `FlowCanvas`, `FlowNodeCard`, `FlowEdge`) from
  the internet through entry points and hops to the asset, the choke points
  ("Fix this to cut N of M paths", each with "View finding" and "View N
  findings", where N is the node's `open_findings` and the link opens exactly
  that list), and the score of the selected path as its step weights and
  their product. Targets come from the exposure chains (crown jewels first);
  `?target=` opens any asset in scope, `?paths=all` shows every route (default:
  the shortest), `?view=list` the list view.
- Hover or focus on a node lights every shown route through it and dims the
  rest to 30 %; a choke-point row lights its node. The selected route is drawn
  in the signal colour, alternatives dotted; edge width follows the step
  weight. Under reduced motion the selected route is solid and static.
- Keyboard: one node is in the tab order; the arrow keys follow the edges
  (right to the next step, left to the previous one, up and down within a
  column), `[` and `]` switch the selected route, Enter opens the step's
  findings, Escape clears the highlight. Each node's name is its visible text,
  with the step weight and its basis as the description.
- The list view (an ordered list per route, each step naming the finding that
  enables the next move) is the default on a phone.
- The side cards sit beside the canvas from 1536 px; below that they go under
  it, so a three-step route is drawn at full size at 1440 px.
- `/exposure-chains` lists the shortest chain per dangerous asset; each chain
  links to the attack-path view of its target.
- A failed read shows an error state with Retry; "No relationship data yet",
  "No path reaches a dangerous asset" and "No path from the internet reaches
  this asset" appear only when the read succeeded.
- A hidden step (see Data scope) renders as a dashed "Outside your access"
  node without a link or weight, and the route's likelihood reads "Withheld".
- All text goes through the `prioritization.*` keys in the en and vi
  dictionaries.
