# Scoping

**CTEM Stage 1.** Before you can reduce risk you have to decide *what's in scope*
and *what matters most*. Scoping is where you define your attack surface, tell the
platform which assets are business-critical, and run the CTEM program itself as
repeatable cycles. These pages live under the **Scoping** sidebar section.

## The CTEM cycle (start here)

**Scoping → CTEM Cycles** (`/cycles`) is the heartbeat of the program. A cycle is
a time-boxed pass through all five stages, with a frozen scope and a charter, so
each round is measurable and comparable to the last.

**Run a cycle end to end:**

1. Click **New Cycle**, give it a **Name**, optional description, and **Start /
   End Date**, then **Create**. The cycle starts in **planning**.
2. Fill in the **Charter** (scope, objectives) while it's in planning.
3. **Activate** the cycle. This freezes its scope into an immutable snapshot —
   you'll be asked to confirm, because the scope can't be edited afterward. The
   cycle moves to **active**.
4. When the work is done, **Start Review** (→ **review**), capture **Scope
   Notes** (refinements and lessons learned), then **Close** the cycle
   (irreversible; → **closed**).

When you create the next cycle, the lessons from the previous closed cycle are
carried forward as a callout, so the program improves each round. The **operating
rhythm** card shows a reference cadence (weekly triage, monthly steering,
quarterly scope refresh) anchored to the active cycle.

> Cycle status flows **planning → active → review → closed**, and each transition
> is guarded by a confirmation. Only closed cycles show a "Completed" badge.

## Define your scope

**Scoping → Scope Config** (`/scope-config`) is where you draw the boundary of
what the platform looks at. It has four tabs:

- **In-Scope Targets** — **Add Target** (type + value + description) for each
  domain, IP range, or asset you want covered.
- **Exclusions** — **Add Exclusion** (type + value + reason) for anything that
  must never be scanned.
- **Scan Schedules** — **Create Schedule** (name, targets, cadence) to scan the
  scope automatically on a recurring basis.
- **Overview** — a summary of the above.

**Scoping → Attack Surface** (`/attack-surface`) gives you the external view —
the internet-facing footprint the platform has discovered for your scope.

## Tell the platform what matters

Risk scoring and prioritization lean heavily on *business context*. Set it here:

- **Business Units** (`/business-units`) — model your org. **Add Business Unit**
  (name, description, **Criticality**, owner, tags); edit or **Export** as needed.
  Business-unit criticality feeds each asset's effective criticality.
- **Crown Jewels** (`/crown-jewels`) — designate your most valuable assets. Click
  **Add Crown Jewel**, search for the asset, add **Business Impact Notes**, and
  **Designate** it. These get extra weight everywhere risk is ranked.
- **Asset Groups** (`/asset-groups`) — organize assets for reporting and
  data-scoping. **New Group** (name, environment, criticality), then **Add Assets
  to '{group}'** with the asset picker. Groups also drive the access-control
  "Teams" feature (see [Team & Access](02-team-and-access.md#teams-data-scope-groups-and-assignment-rules)).
- **Business Services** (`/business-services`) — group assets by the service they
  deliver, so you can reason about risk to a service rather than to raw hosts.

> **Setting an asset's own criticality** is done in bulk from the unified
> inventory — select assets and use **Set criticality**. See
> [Discovery → Asset inventory](04-discovery.md#asset-inventory). An asset's
> *effective* criticality is the highest of its own, its business unit's, and its
> service's.

## Model the threat

- **Attacker Profiles** (`/attacker-profiles`) — describe the adversaries you care
  about (motivation, capability), which informs threat modeling and prioritization.
- **Threat Model** (`/threat-model`) — continuous threat modeling that maps how
  those attackers could reach your crown jewels.
- **Relationships** (`/relationships/suggestions`) — review and confirm suggested
  connections between assets, enriching the graph that attack-path analysis uses.

## Compliance

**Scoping → Compliance** (`/compliance`) maps your posture to compliance
frameworks and tracks assessment coverage, so exposure work can be tied back to
the controls it satisfies.
