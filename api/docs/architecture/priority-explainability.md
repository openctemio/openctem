# Priority Explainability

> "Why is this finding P0?" — a read-only breakdown of the factors and the
> decision behind a finding's priority class, so operators can audit and tune
> prioritization instead of treating it as a black box.

## Endpoint

```
GET /api/v1/findings/{id}/priority-explanation      (permission: findings:read)
```

Returns the class the finding holds and the classification the engine would
compute for it **right now**, without mutating it or emitting events. When a
person overrode the class, the decision fields report that override
(`source: "manual"`) and the engine's verdict stays visible in
`computed_class`. Response:

```jsonc
{
  "finding_id": "…",
  "priority_class": "P0",
  "reason": "In CISA KEV (known exploited) and reachable (from 1 entry points)",
  "source": "auto",              // "auto" (default classifier), "rule" (tenant rule) or "manual" (a person's override)
  "rule_name": null,             // set when source == "rule"
  "override": null,              // {"by": "<user id>", "at": "<time>"} when a person set the class
  "computed_class": "P0",        // what the engine computes now (rules and platform floors included)
  "computed_reason": "…",
  "stored_class": "P0",          // what the finding holds now ("" when never classified)
  "stored_reason": "…",
  "stale": false,                // automatic class differs from computed_class: a recompute is pending, or the finding is closed (frozen)
  "model_version": 2,            // priority model version of this build (scoring-versions.md)
  "factors": {
    "severity": "critical",
    "cve_id": "CVE-2021-44228",
    "epss_score": 0.97,
    "epss_percentile": 99.9,        // 0–100 rank (canonical scale everywhere); epss_score is the 0–1 probability
    "is_in_kev": true,
    "validated_exploitable": false, // the latest validation re-check reproduced the finding
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
   A control counts only when it is active, has a passing test, its review
   date (`expires_at`, at most 366 days ahead, 90 days when a control is created without one; an update cannot clear it) has not passed, and
   its reduction is at least 0.25. It then lowers the class by at most one
   level, never raises it, and never takes a CISA KEV finding below P1; the
   reason names the step ("lowered one level to P2 (was P1): compensating
   control, 40% reduction").
4. Evaluate tenant **override rules** first (first match wins → `source: "rule"`,
   `rule_name`); otherwise the default `ClassifyPriority` (`source: "auto"`).
   Rules are evaluated by `evaluation_order` (highest first), ties broken by
   creation time then id, so the same rule wins on every pass.
5. Apply the platform floors to the result, rule results included (below).
6. When the finding carries a manual class override, report it as the
   decision (`source: "manual"`, `override`), keeping the computed class
   beside it.

## Platform floors (priority model v2)

Some classes are platform rules, not tenant settings. They run after the
base class, compensating controls, the business-impact bump, the AI
false-positive step and every tenant rule:

- **Exploitation floor** (`vulnerability.ApplyExploitationFloor`): a finding
  with exploitation evidence (its CVE is in CISA KEV, or the latest
  validation re-check reproduced it, `validation_outcome = reproducible`) is
  at least **P1**, whatever the exposure, scanner severity, controls or
  rules. The reason adds "floor applied: raised to P1 from P3, in CISA KEV
  (known exploited)". Only the attribution cap (P2 until the asset is
  confirmed as the tenant's) runs after it.
- **AI triage never changes the class**: an AI verdict reads scanner output
  an attacker can influence, so it is a suggestion for a person. A confident
  "likely false positive" on a medium or low finding becomes a pending
  false-positive request; the priority class is never lowered by it
  ([AI triage](ai-triage.md)).
- **Rules raise freely, lower only to the floors**: a rule result passes
  through the exploitation floor and the attribution cap
  (`ruleClassification`). Creating, changing or deleting a rule needs a
  recent sign-in (step-up, [step-up re-authentication](step-up-reauth.md)).
  The rule dry run (`POST /api/v1/priority-rules/dry-run`) classifies the
  tenant's open findings with the real engine, floors included, up to 20,000
  findings: `open_findings` is the tenant total, `capped` marks a sample, and
  `floored` counts matches a floor keeps above the rule's class. It is rate
  limited to 6 per minute per tenant.

KEV membership no longer rewrites a finding's severity: KEV is exploitation
evidence and reaches priority through the floor, so the scanner's or an
analyst's severity stands and KEV is not counted twice. Severities raised to
critical by earlier versions are kept (forward only).

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
- `attribution_unconfirmed` — the asset's attribution state (`needs_review`,
  `candidate` or `rejected`) when it caps the class (RFC-036 §6.8, decision
  T5): a finding on an asset the platform has not confirmed as the tenant's
  is held at **P2**, whatever the base class, bumps or override rules say. The
  cap runs last (`vulnerability.ApplyAttributionCap`, also applied to rule
  results) and adds "capped at P2 until ownership is confirmed (was P0; asset
  attribution: needs_review)" to the reason; the finding page shows a
  "Verify ownership" note linking to the asset. `dependency` and
  `monitor_only` (a person's decision that the name is the tenant's), confirmed
  and legacy assets (no record) are never capped. One tenant-scoped lookup per
  batch (`AttributionRepository.ActiveCheckBlocked`); a lookup error means no
  cap, never a failed classification.

- `reachability_unknown` — nothing decided reachability: the asset's exposure
  is unknown and no attack path, threat path or scanner flag says otherwise
  (typically a dependency in a repository). Unknown is not unreachable: the
  reason says "reachability unknown", never "not reachable", and exploitation
  evidence still makes the finding P1 (a KEV CVE, EPSS >= 50%, or EPSS >= 10%
  on a critical or high asset). Severity alone stays at P2 until reachability
  is known. An isolated asset is evidence of unreachability; a private or
  restricted one of internal-only reachability, and the reason names it.

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
