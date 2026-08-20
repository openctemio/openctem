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
    "on_open_threat_path": true,
    "reachable_from_count": 1,
    "asset_criticality": "high",
    "asset_exposure": "public",
    "asset_is_crown_jewel": true,
    "asset_unowned": false,
    "is_protected": false,
    "control_reduction_pct": 0,
    "cia_impact_score": 5,          // 0–5 MAX leg from the asset's CIA register
    "cia_impact_detail": "confidentiality=high",
    "reachable": true,              // derived: is_reachable || is_internet_accessible || on_open_threat_path
    "critical_asset": true          // derived: criticality in {critical, high}
  },
  "score_breakdown": {              // transparent CTEM composite (explains, does not decide)
    "impact": 5,                    // 0–5
    "likelihood": 5,                // 0–5 (KEV + EPSS)
    "exposure": 4,                  // 0–5 (internet/threat-path reachability)
    "control_reduction": 0,         // 0–0.5 (validated compensating controls)
    "score": 14                     // (impact + likelihood + exposure) × (1 − control_reduction), 0–15
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

## Transparent composite score (`score_breakdown`)

Alongside the class, the endpoint returns `score_breakdown` — the ctem.org
prioritization composite computed from the **same** `PriorityContext`
(`vulnerability.ComputePriorityScore`, `pkg/domain/vulnerability/priority.go`):

```
PriorityScore = (Impact + Likelihood + Exposure) × (1 − ControlReduction)
```

Impact, Likelihood and Exposure are each 0–5; ControlReduction is 0–0.5 (never
more than halves the score), so the composite lands in 0–15. It is **additive
transparency** layered on top of the authoritative `classifyBase → P0–P3`
cascade — computing the score never changes the bucket a finding lands in, and
because it is derived from the same context the number cannot drift from the
decision it explains.

## Newer factors

Beyond the classic inputs, the explanation now also surfaces:

- `cia_impact_score` / `cia_impact_detail` — the 0–5 CIA business-impact leg
  (MAX) from the asset's Scoping critical-asset register, folded into `impact`
  as an only-raise MAX.
- `on_open_threat_path` — the finding sits on an open attack/threat path.
- `is_network_accessible` — network-reachability input distinct from
  internet-facing exposure.
- `asset_unowned` — surfaced when the tenant's ownership floor is enabled.

> Reachability inputs are populated from the asset's exposure level and
> attack-path membership. `reachable` follows the engine formula
> `is_reachable || is_internet_accessible || on_open_threat_path` (the
> threat-path term was added so a finding on an open path counts as reachable
> even when the asset is not directly internet-facing).

## Layering

| Layer | File |
|-------|------|
| Service | `internal/app/finding/priority_explanation.go` (`ExplainFinding`) |
| Domain logic | `pkg/domain/vulnerability/priority.go` (`ClassifyPriority`) |
| Handler | `internal/infra/http/handler/vulnerability_handler.go` (`ExplainPriority`) |
| Route | `internal/infra/http/routes/exposure.go` (findings group) |

The handler depends on the service through the narrow `PriorityExplainer`
interface; when unwired the endpoint returns 404.
