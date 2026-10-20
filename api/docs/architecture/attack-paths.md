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
tenant for a short time with concurrent callers sharing one computation. The
HTTP endpoint, the MCP tool, the priority oracle and threat-model generation all
read the same cache; only the HTTP and MCP responses apply a row cap, after the
caller's data scope.

## Data scope

Planned in this series; see the section below once shipped.

## Linear computation

Planned in this series; see the section below once shipped.

## Scoring cache and finding counts

Planned in this series; see the section below once shipped.
