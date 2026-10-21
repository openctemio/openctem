# Attack paths

How the platform answers "which assets can the internet reach, and through what".
Two read endpoints share one in-memory graph built from the tenant's assets and
relationships on each computation:

```
GET /api/v1/attack-surface/attack-paths      (assets:read, module attack_surface)  ranked assets
GET /api/v1/attack-surface/exposure-chains   (assets:read, module attack_surface)  shortest chain per dangerous asset
```

Key code: `api/internal/app/attack/` (`path_scoring.go`, `exposure_chains.go`,
`scoped.go`), the priority oracle in `api/cmd/server/reachability_oracle.go`, the
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

- `/attack-paths` ranks assets by the score above. Each row is the asset itself;
  the page makes no claim about which fix breaks the most paths (no choke-point
  analysis exists yet). `/exposure-chains` draws the real hop chains.
- A failed read shows an error state with Retry on both pages; the
  "No relationship data yet" state appears only when the read succeeded and the
  tenant has no relationships.
- A hidden step (see Data scope) renders as a dashed "Outside your access" card
  without a link.
- All text goes through the `prioritization.*` keys in the en and vi
  dictionaries.
