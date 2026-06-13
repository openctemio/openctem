# Priority Explainability

> "Why is this finding P0?" — a read-only breakdown of the factors and the
> decision behind a finding's priority class, so operators can audit and tune
> prioritization instead of treating it as a black box.

## Endpoint

```
GET /api/v1/findings/{id}/priority-explanation      (permission: findings:read)
```

Returns the classification the engine would compute for the finding **right
now**, without mutating it or emitting events. Response:

```jsonc
{
  "finding_id": "…",
  "priority_class": "P0",
  "reason": "In CISA KEV (known exploited) and reachable (from 1 entry points)",
  "source": "auto",              // "auto" (default classifier) or "rule" (tenant override)
  "rule_name": null,             // set when source == "rule"
  "factors": {
    "severity": "critical",
    "cve_id": "CVE-2021-44228",
    "epss_score": 0.97,
    "epss_percentile": 0.99,
    "is_in_kev": true,
    "is_reachable": false,
    "is_internet_accessible": true,
    "is_network_accessible": false,
    "reachable_from_count": 1,
    "asset_criticality": "high",
    "asset_exposure": "public",
    "asset_is_crown_jewel": true,
    "is_protected": false,
    "control_reduction_pct": 0,
    "reachable": true,           // derived: is_reachable || is_internet_accessible
    "critical_asset": true       // derived: criticality in {critical, high}
  }
}
```

## What it computes

`PriorityClassificationService.ExplainFinding` mirrors the live classify path
(`ClassifyFinding`) exactly — same inputs, same precedence — but is read-only:

1. Load the finding and (best-effort) its asset.
2. Build the `PriorityContext` (severity, EPSS, KEV, reachability, asset
   criticality/exposure/crown-jewel).
3. Apply compensating-control reduction (`is_protected` / `control_reduction_pct`).
4. Evaluate tenant **override rules** first (first match wins → `source: "rule"`,
   `rule_name`); otherwise the default `ClassifyPriority` (`source: "auto"`).

The two **derived** booleans (`reachable`, `critical_asset`) are surfaced
because they are what the P0/P1 gates actually test — exposing them makes the
"reason" line auditable rather than opaque.

> Reachability inputs are populated from the asset's exposure level (see the
> reachability fix in the priority classifier). `reachable` follows the engine
> formula `is_reachable || is_internet_accessible`.

## Layering

| Layer | File |
|-------|------|
| Service | `internal/app/finding/priority_explanation.go` (`ExplainFinding`) |
| Domain logic | `pkg/domain/vulnerability/priority.go` (`ClassifyPriority`) |
| Handler | `internal/infra/http/handler/vulnerability_handler.go` (`ExplainPriority`) |
| Route | `internal/infra/http/routes/exposure.go` (findings group) |

The handler depends on the service through the narrow `PriorityExplainer`
interface; when unwired the endpoint returns 404.
