# Criticality Propagation

> How an asset's **effective (business-aligned) criticality** is raised above its
> own criticality by the business context around it — business units, business
> services, and the control-plane graph — with multi-hop, cycle-guarded
> propagation (api #481).

## The rule

`EffectiveCriticality` (`pkg/domain/asset/business_criticality.go`) is the shared
MAX/floor rule used by **both** finding-priority classification and asset
`risk_score`, so the two can never disagree:

```
EffectiveCriticality = MAX(
    own criticality,
    business-unit criticality,
    business-service criticality,
    control-plane-served criticality
)
```

**Floor / only-raise semantics:** the result is never below the asset's own
criticality, and a lower-criticality signal leaves it unchanged. When a signal
raises it, an audit reason names the source (e.g. "raised to critical by business
unit 'Payments'").

## The two graph walks (api #481)

Both live as **pure, DB-free, unit-tested** traversals in
`internal/infra/postgres/criticality_propagation.go`, separated from the
repository so their invariants (multi-hop, cycle termination, depth cap) are
testable without a database.

- **Control-plane propagation — `walkControlPlane`.** A control plane of a
  critical asset is itself critical: compromising the IdP/SSO, secrets store,
  CI/CD, or SIEM that a business asset relies on pulls in everything it serves.
  The walk goes backward from a candidate control-plane asset across bounded
  **multi-hop** `is_control_plane` edges (migration `000207`) and returns the MAX
  criticality among every asset it transitively serves. Only raises; returns the
  zero criticality when it serves nothing.

- **Business-unit hierarchy — `resolveBUCriticality`.** A BU's effective
  criticality is the MAX of its own and every ancestor's along the
  `business_units.parent_id` chain (migration `000188`, `ON DELETE SET NULL`,
  no-self-parent CHECK). Inherited down the tree so a child BU never scores below
  its more-critical parent.

Both are **bounded by a depth cap and guarded by a visited set**, so a malformed
or cyclic parent/edge chain terminates instead of looping.

## Where it feeds

- **Finding priority** — `internal/app/finding/priority_explanation.go` builds
  the classifier's `PriorityContext` from `EffectiveCriticality`, and surfaces
  the raise reason (see `priority-explainability.md`).
- **Asset risk_score** — consumes the same effective value.

## Related

- `asset-schema.md` — CIA impact register + `is_control_plane` edge.
- `priority-explainability.md` — how effective criticality reaches a finding's
  priority class.
