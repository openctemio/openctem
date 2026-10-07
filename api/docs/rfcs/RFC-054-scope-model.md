# RFC-054: Scope model (what a tenant may actively probe)

| | |
|---|---|
| Status | Accepted (owner decisions S1–S6, 2026-10-07); P0 in implementation |
| Scope | api (`pkg/domain/scope`, `internal/app/scope`, `internal/app/actscope`, `internal/app/easm`, `internal/app/scan`, `internal/app/certmonitor`, handlers, migrations), web (Scoping, scan dialog), sensor-local policy (follow-up) |
| Architecture | [active-probe-gate.md](../architecture/active-probe-gate.md) |
| Related | RFC-023 (zones), RFC-036 §6.3/§6.4 (ownership gate, attribution), RFC-040 §5.6 (widening approvals, amended here), RFC-042 §6.13 (wildcard semantics, superseded here), RFC-050 (data scope) |

## 1. Summary

Several records decide whether a target may be probed today: scope targets,
root-domain seeds, verified domains, attribution states and inventory
membership, with exclusions, scan zones and freeze windows on top. They
disagreed with each other, widening scope was one unaudited click, and a
refusal said nothing about how to fix it.

This RFC makes one model out of them:

1. **`*.x` means `x` and every name below it** (S1). An exclusion of exactly
   `x` carves the apex out.
2. **One authority check** decides for every target, typed or inventory, on
   every path. An asset's ownership record alone never authorizes an active
   probe; a scope entry, seed or verified domain must cover it.
3. **Names covered by a permanent scope entry or seed are confirmed** into the
   inventory (S4): IP addresses only through IP entries; expiring entries
   never confirm; tombstones and exclusions win.
4. **Expiring entries** replace "exceptions" (S6): `expires_at` + `reason`,
   default 7 days, at most 30; expired entries stop authorizing at once.
   Members request; approvers create and approve.
5. **Widening is the guarded direction** (S3): step-up re-authentication on
   every widening route, a tenant approval count of 0/1/2 (default
   `min(1, admins − 1)`, never 0 for intrusive entries), every administrator
   notified, everything audited.
6. **Structured refusals**: every refused target carries a code, the rule that
   decided, and the fixes the caller may apply. `POST /scope/check` is a dry
   run of the whole gate.
7. **Platform guardrails** (S2), operator-level only: active-probe proof
   (`SCOPE_ACTIVE_PROOF`), public-suffix refusal, a minimal platform deny list
   and CIDR size caps.
8. **Tenant settings** (S5): auto-join, who adds one-off targets, maximum
   days, approval count, default tier. There is **no** switch that turns
   scope off.

## 2. Threat model

| Actor | Goal | Control |
|---|---|---|
| Careless admin | types `vndirect.com` for `vndirect.com.vn` | preview (`POST /scope/check`), step-up, second approver when the tenant has two or more admins, admin notification |
| Compromised admin session | adds `*.victim.com` and scans it | step-up on every widening route (a stolen cookie alone cannot widen), approvals, notification of every admin, audit |
| Malicious tenant (colluding admins) | uses the platform to scan a third party | approvals do not help; **ownership proof** for probes from platform sensors (`SCOPE_ACTIVE_PROOF`), platform deny list, public-suffix refusal, CIDR caps; none of them tenant-overridable |
| Restricted member | scans outside their assets | act scope (D9) unchanged; may only *request* a one-off entry |
| DNS pointing to others' IPs | an in-scope name resolves to a third party's address | a name grant never becomes an IP grant: discovered addresses never inherit (S4); the sensor resolves and pins (local policy) |
| Ownership-tab click | confirms `bank.example` as the tenant's and scans it | confirmation no longer authorizes alone (§4.2) |
| Cross-tenant oracle | learns that another tenant verified or scoped a name | every lookup is tenant-scoped; refusal reasons name only the caller's own rules or "platform policy" |

Every query is tenant-scoped (`tenant_id` from the authenticated context).
Every lookup error refuses (fail closed).

## 3. Decisions

| # | Decision |
|---|---|
| S1 | (a) `*.x` = `x` + all subdomains; exclusion `x` carves the apex out |
| S2 | (a) proof for active probes is an operator setting `SCOPE_ACTIVE_PROOF`: SaaS default `platform_sensors`, self-hosted `off`; intrusive (T2) always needs proof |
| S3 | (a) widening approvals are a tenant setting 0/1/2, default `min(1, admins − 1)`, never 0 for T2 (amends RFC-040 Q2 (a)) |
| S4 | yes, refined 2026-10-07: an active, non-expiring scope entry or seed confirms the names it covers (`matches_scope_target`, no review); IPs only through IP entries; one-off entries never confirm; tombstones and exclusions win; removal keeps the asset and stops scanning; backfill of existing `needs_review` rows |
| S5 | tenant knobs (§7); no global scope-off switch, ever |
| S6 | one-off = a scope entry with `expires_at` + `reason`; admins create, members request; default 7 days, max 30 |

## 4. Semantics

### 4.1 Domain patterns

| Pattern | Covers |
|---|---|
| `x` | exactly `x` |
| `*.x` (and `**.x`) | `x` and every name below it, at any depth |
| `*.x` + exclusion `x` | the subdomains of `x`, not `x` |

Matching is case-insensitive, ignores one trailing dot and compares IDNA ASCII
forms. Scope targets and exclusions use the same matcher
(`pkg/domain/scope.matchDomain`), and so do seeds, verified domains and the
active-scan gate.

**Upgrade note.** Existing `*.x` scope targets start covering their apex, and
existing `*.x` exclusions start excluding it. Live had 3 wildcard targets, 1 of
them without its own apex row (counted 2026-10-07). A tenant that needs the
apex out adds an exclusion of exactly `x`.

**Sensor-local policy.** The sensor's operator-written policy
(`targets.allow`/`deny`, sdk-go `pkg/core/local_policy`) still reads `*.x` as
"names below `x`". That is the stricter reading on an allow list, so nothing is
probed that the platform would refuse; a follow-up sdk-go/sensor change aligns
it with this section.

### 4.2 One authority check

A target (typed text or inventory asset) may be actively probed only when all
of these hold, in order (`scan.Service.ResolveDispatchTargets` and the scan
trigger):

1. the scan target validator accepts it (no loopback, link-local, metadata;
   private addresses only inside a scan zone);
2. the platform deny list does not cover it (§8);
3. no active exclusion matches it;
4. the tenant did not reject it or a parent name of it (tombstone or rejected
   asset);
5. its attribution record, if any, is `confirmed`;
6. **authority**: an internet-facing target is covered by an *active* scope
   entry (approved, unexpired) with `max_tier` at or above the probe's tier, or
   sits at or under a root-domain seed or a verified domain of purpose `easm`
   (T1 at most). A domain verified for SSO sign-in (purpose `sso`, set up by
   a platform administrator) never authorizes; it counts only as proof
   (step 7). A target covered only below the probe's tier is refused
   `tier_exceeds`. The
   probe's tier is its tool's highest stage tier (an unknown tool is T1): scan
   create and quick scan refuse the request, a run leaves the target out with
   a warning (`TIER_EXCEEDS` when nothing is left), a workflow step is checked
   at its own tool's tier, and the dispatch gate (pipeline runs, chained hops,
   coverage, validation, the dry run) checks T1 unless told otherwise;
7. proof, when §8.1 requires it: the target sits at or under a verified domain;
8. the actor may act on it (D9: data scope; restricted members only their
   assets);
9. scan-zone routing.

Private addresses and internal names are gated by zones, not by step 6.
Repositories and cloud resources keep the record-only rule until their
connectors become proof (P1).

Steps 1–9 run on every path: scan create/clone/import/quick scan, scan runs
(manual, scheduled, workflow, retry), `POST /pipelines/runs`, the coverage
dispatcher, every validate command (retests, proof-of-fix, simulations),
connector scans, CI-triggered scans and EASM active stages. Passive (T0)
stages keep only steps 1–4.

**Ownership tab.** Before this RFC, a person confirming an asset on its
Ownership tab authorized it for active checks even outside every root. Now
confirmation records ownership only; a scope entry, seed or verified domain
must still cover the name. The refusal offers "add scope entry".

### 4.3 Discovered names (S4, owner refinement 2026-10-07)

A declared, permanent scope entry is an intentional ownership claim, made with
step-up and approval (§6.1, §7). So:

- **Rule `matches_scope_target`** (strong, weight 0.99): a domain name that a
  tenant **active, non-expiring** domain scope target covers (`x`, or `*.x` /
  `**.x` under §4.1), or that sits at or under one of its root-domain seeds, is
  **confirmed** into the inventory. No review queue. The decision is recorded
  as automatic (not human), with the matching entry in the evidence, and is
  audited as a system decision.
- **IP addresses never inherit from names.** An IP asset is confirmed by this
  rule only when an active, non-expiring `ip_address`, `ip_range` or `cidr`
  scope entry contains it. Services follow their host.
- **Expiring (one-off) entries authorize scanning only** and never confirm
  inventory.
- **Exclusions and tombstones win**: an excluded name, a tombstoned name or a
  name under a rejected parent never gets the rule.
- **Not proof.** Confirmation is ownership bookkeeping; §8.1 (platform sensors
  need a verified root) is unchanged.
- The tenant setting `auto_join_discovered` (default on) turns the rule off:
  new names then go to the review queue as before.
- Every other discovered name keeps today's evidence and lands in the existing
  attribution review queue.

The rule is applied wherever discovered names are attributed: CT promotion
and the scan stamper (names a tenant scan found).

**When the entry goes away** (deleted, deactivated, narrowed or expired): the
asset, its history and findings stay; nothing is deleted. Active scanning stops
at once, because the authority check (§4.2 step 6) no longer finds a cover;
the asset's attribution view answers `scope_status: "out_of_scope"` and the
refusal code `no_entry`.

**Backfill.** A one-shot job re-evaluates the records that are `needs_review`
(for example reason `fqdn_under_asserted_root`) and not human-decided: each
name now covered by an active, non-expiring scope target or a root-domain seed
of the **same tenant** (and not excluded, not tombstoned, not under a rejected
name, `auto_join_discovered` on) gets the `matches_scope_target` evidence and
is re-evaluated, which confirms it. Idempotent (evidence upserted per asset,
rule and source; confirmed records are left alone), per tenant, one system
audit event per tenant (`attribution.backfill_confirmed`, the count and up to
50 names). It runs at API start-up, recorded once per tenant. Live had 10 such
names under `*.vndirect.com.vn` (2026-10-07).

Tests: a wildcard match confirms; an expiring entry does not; an IP does not
(unless inside an IP scope entry); an exclusion or tombstone blocks; removing
the entry flags the asset out of scope and stops active checks; another
tenant's entries have no effect.

### 4.4 Inventory membership (one definition)

An asset is **in the inventory** when its attribution is confirmed (recorded,
or no record: a legacy asset), `dependency` or `monitor_only`
(`attribution.FilterApproved`). The review queue (`needs_review`,
`candidate`) and `rejected` assets are not. Every surface uses this one
definition: the Assets list default, dashboard and attack-surface counts and
trends, and attack-surface "recent changes". A change event whose asset is not
in the inventory is still listed in recent changes, but carries its
attribution state so the UI shows "Added · needs review" instead of "Added".

## 5. Data model (migration `001198`)

`scope_targets` gains:

| Column | Type | Default | Meaning |
|---|---|---|---|
| `expires_at` | timestamptz NULL | NULL (permanent) | expiring entries; expired ones never authorize |
| `reason` | text NOT NULL | `''` | authority statement; required for expiring entries and requests |
| `max_tier` | smallint NOT NULL, 0–2 | 1 | ceiling for probes authorized by this entry |
| `approvals_required` | smallint NOT NULL, 0–2 | 0 | approvals the entry needs before it authorizes |
| `approved_at` | timestamptz NULL | `created_at` for existing rows | when it became effective |
| `rejected_by`, `rejected_at` | uuid / timestamptz NULL | — | a declined request |

`status` adds `pending`, `rejected` and `expired` to `active`/`inactive`.
`scope_target_approvals (tenant_id, target_id, approver_id, approved_at)`
records each approval (composite tenant foreign key, one row per approver).

Permission `attack_surface:scope:approve` (owner and admin by default)
creates effective entries and approves requests and widening changes.

## 6. API contract

All routes are under `/api/v1/scope`, tenant from the token, module
`scope_config`. "Step-up" means `403 STEP_UP_REQUIRED` until the session
re-authenticated within the step-up window (the web client's existing
re-authentication dialog handles it).

### 6.1 Scope entries

**`POST /targets`** (`scope:write`)

```json
{
  "target_type": "domain",
  "pattern": "*.example.com",
  "description": "",
  "reason": "We own it (registrar account 123)",
  "expires_in_days": 7,
  "expires_at": "2026-10-14T00:00:00Z",
  "max_tier": "t1",
  "priority": 0,
  "tags": []
}
```

`expires_in_days` (1 – `one_off_max_days`) or `expires_at` (future, within the
same bound) makes the entry a one-off; neither makes it permanent.
`max_tier` defaults to the tenant's `default_max_tier`.

- Caller holds `scope:approve`: **step-up**. The entry needs
  `approvals_required = effective_widening_approvals` (raised to at least 1
  for `t2`). With 0 it is `active` at once; otherwise `pending`.
- Caller lacks `scope:approve`: the entry is a **request**: it must be a
  one-off for a single name or address (no wildcard, no range), `reason` is
  required, the tenant's `one_off_targets` must be `admins_and_requests`, and
  it is `pending` with `approvals_required = max(1, effective)`. No step-up
  (a request authorizes nothing).
- `t2` needs an expiry and at least one approval.
- Refused patterns answer `400` with codes `PUBLIC_SUFFIX`, `DENY_LIST`,
  `CIDR_TOO_LARGE`, `ONE_OFF_TOO_LONG`, `REASON_REQUIRED`,
  `REQUEST_NOT_ALLOWED`, `REQUEST_MUST_BE_SINGLE`.

Response (`ScopeTargetResponse`, also for list/get/update):

```json
{
  "id": "…", "tenant_id": "…", "target_type": "domain", "pattern": "*.example.com",
  "covers": "domain_and_subdomains",
  "description": "", "reason": "…", "priority": 0, "tags": [],
  "status": "pending",
  "expires_at": "2026-10-14T00:00:00Z",
  "max_tier": "t1",
  "approvals_required": 1,
  "approvals": [{"user_id": "…", "approver": {"kind": "user", "id": "…", "name": "Lan"}, "approved_at": "…"}],
  "approved_at": null,
  "rejected_by": null, "rejected_at": null,
  "created_by": {"kind": "user", "id": "…", "name": "Nguyen Manh"},
  "origin": "manual",
  "created_at": "…", "updated_at": "…",
  "warnings": ["Pattern \"*.example.com\" is a superset of existing pattern \"api.example.com\""]
}
```

`covers` is `name`, `domain_and_subdomains`, `addresses` or `pattern`.

**People and provenance.** Every actor field of an entry or exclusion
(`created_by`, `approvals[].approver`, `rejected_by`, and an exclusion's
`approved_by`) is an `ActorRef`:

```json
{ "kind": "user", "id": "019d…", "name": "Nguyen Manh" }
{ "kind": "user", "id": "…", "former_member": true }
{ "kind": "system", "code": "upgrade_wildcard_split" }
```

Names come only from the organization's current members (active or
suspended); a user who left, or an id that is not a member, is a
`former_member` with no name. No e-mail is returned. System codes:
`upgrade_wildcard_split` (the 000292 apex rows), `seed_migration`, `system`.
`origin` is how the row came to exist: `manual`, `request` (a member's
request), `import`, `review_rule`, `refusal_fix` (the one value a client may
send on create, when it fixes a refused scan target), `seed`,
`seed_migration` or `system` (migration `001244`, existing rows `manual`,
platform rows `system`). Audit records keep the reference without the name.
`status` is `active`, `pending`, `inactive`, `rejected` or `expired`.

**Seeds** (`POST /api/v1/easm/seeds`, `scope:approve` + **step-up**): a
root-domain seed authorizes T1 probes of every name under it and confirms
them (§4.3), so a new seed is created as the permanent entry `*.<domain>`
through the path above (approval count, guardrails, notification, audit
`scope_target.created` with `via: easm_seed`). The answer is the entry:
`201` when it is active, `202` when it is pending. A member gets `403
WIDENING_NEEDS_APPROVER` (members request one-off entries here). Turning a
seed's discovery on (`PATCH /easm/seeds/{id}`) needs `scope:approve` and
step-up and notifies the administrators. Seed rows created before this rule
keep working until they fold into entries.

**`POST /targets/{id}/approve`** (`scope:approve`, **step-up**): records the
caller's approval. The requester cannot approve; nobody approves twice. When
the distinct approvals reach `approvals_required`, the entry becomes `active`.
`409 ENTRY_NOT_PENDING` for anything not pending; `409 ENTRY_EXPIRED` when it
expired while pending.

**`POST /targets/{id}/reject`** (`scope:approve`): `pending` → `rejected`.

**`PUT /targets/{id}`** (`scope:write`): `description`, `priority`, `tags`,
`reason`, `expires_at`, `expires_in_days`, `clear_expiry` (bool), `max_tier`.
A **widening** change (a later or removed expiry, a higher tier) needs
`scope:approve` and **step-up**, and sends the entry back to `pending` when
`approvals_required` > 0 (as an exclusion's extended window does). A narrowing
change (earlier expiry, lower tier) applies at once.

**`POST /targets/{id}/activate`**: widening. It needs `scope:approve`
(`403 WIDENING_NEEDS_APPROVER` otherwise) and step-up, then the entry is
`active` or `pending` as for create. An expired entry is renewed with a new
expiry through `PUT` instead (`409 ENTRY_EXPIRED`).

While a widened entry is `pending` it authorizes nothing (as an exclusion
whose window was extended); the UI says so before the change.

Errors carry their code: `ONE_OFF_TOO_LONG`, `ONE_OFF_DISABLED`,
`REQUEST_NOT_ALLOWED` (403), `REQUEST_MUST_BE_ONE_OFF`,
`REQUEST_MUST_BE_SINGLE`, `REQUEST_TIER`, `REASON_REQUIRED`,
`INTRUSIVE_NEEDS_EXPIRY`, `WIDENING_NEEDS_APPROVER` (403),
`ENTRY_SELF_APPROVAL` (403), `ENTRY_ALREADY_APPROVED`, `ENTRY_NOT_PENDING`,
`ENTRY_EXPIRED`, `ENTRY_REJECTED` (409), and `STEP_UP_REQUIRED` /
`STEP_UP_UNAVAILABLE` (403).

`POST /targets/{id}/deactivate`, `DELETE /targets/{id}`,
`POST /targets/bulk/delete`: narrowing, unchanged.

### 6.2 Exclusions

Unchanged, except that the widening exclusion routes require **step-up**:
`DELETE /exclusions/{id}`, `POST /exclusions/{id}/deactivate`,
`POST /exclusions/bulk/delete`, and `PUT /exclusions/{id}` when it shortens
the window. The approval rule (approver ≠ requester) stays.

**Path exclusions (RFC-056 §5, migration `001231`).** An exclusion of type
`path` is a web rule, not an asset exclusion:

- `POST /exclusions` with `exclusion_type: "path"` takes `pattern` as a host
  pattern (`*`, `*.example.com` covering the apex as in S1, a host, or an
  origin URL), `path_prefix` (required; segment-aware, `*` only as a whole
  segment, no dot segments or encoded slashes) and `methods` (optional; the
  methods it blocks, empty = every method). The UI suggests a method-scoped
  rule (POST, PUT, PATCH, DELETE) for sensitive paths, so read-only checks
  still run there. The rule cannot be edited later; replace it instead.
- Each path exclusion has a **testing mode**:
  `PUT /exclusions/{id}/testing` `{"testing": "blocked"|"read_only"|"allowed",
  "testing_until": RFC 3339}`. New exclusions are `blocked`; `read_only` lets
  GET and HEAD through; `allowed` treats the path as in scope until
  `testing_until` (at most 90 days), then it is `blocked` again. The route
  needs `attack_surface:scope:exclusions:approve` and step-up, is audited
  (`scope_exclusion.updated` with before and after) and notifies every
  administrator. There is no switch that lifts every exclusion at once (S5).
- Lifting an exclusion never widens scope: a target must still pass the one
  authority check (§4.2) and the tier ceilings, guardrails and deny list
  (§8). A host the exclusion's pattern covers that is not the organization's
  asset stays refused.
- Responses carry `path_prefix`, `methods`, `testing`, `testing_effective`
  (the mode in force now), `testing_until`, `testing_changed_by` and
  `testing_changed_at`.

### 6.3 Settings (S5)

**`GET /settings`** (`scope:read`) and **`PUT /settings`** (`scope:approve`,
**step-up**; every admin notified, audited):

```json
{
  "auto_join_discovered": true,
  "one_off_targets": "admins_and_requests",
  "one_off_max_days": 7,
  "widening_approvals": null,
  "default_max_tier": "t1",

  "effective_widening_approvals": 1,
  "admin_count": 2
}
```

| Field | Values | Default |
|---|---|---|
| `auto_join_discovered` | bool | true |
| `one_off_targets` | `admins`, `admins_and_requests`, `disabled` | `admins_and_requests` |
| `one_off_max_days` | 1–30 | 7 |
| `widening_approvals` | `null` (default), 0, 1, 2 | `null` → `min(1, admins − 1)` |
| `default_max_tier` | `t0`, `t1` | `t1` |

The last two fields are read-only. `effective_widening_approvals` is capped
at `admin_count − 1` (the administrators other than the requester can always
satisfy it), and an organization with two or more admins cannot go below 1
(S3); intrusive entries always need 1. Unset fields fall back to their
default on `PUT`. The operator's `active_proof` (§8.1) is added to this
response by the guardrails PR. `t2` is never a default.

### 6.4 Dry run: `POST /check` (`scope:read`)

```json
{ "targets": ["vndirect.com.vn", "promo-landing.net"],
  "asset_ids": ["5f0c…"],
  "sensor_preference": "auto",
  "tier": 1 }
```

At most 200 targets and assets together, at least one. An inventory asset
(`asset_ids`) is checked by its name, as a scan of it would be (its other
names, such as its address, count for exclusions); its result carries
`asset_id`. An asset outside the caller's data scope, another tenant's, a
deleted or an unknown id all answer the same `out_of_data_scope` with the id
as `target` and nothing else, so the dry run is no existence oracle. Runs §4.2
steps 1–9 for the caller (act scope included) without dispatching, auditing
or logging a refusal. The act scope answers first for a restricted member
(`not_an_asset`, `out_of_data_scope`), so the dry run tells them nothing
about assets outside their data scope; `proof_required` applies with
`sensor_preference=platform` under the operator's proof mode and to
`tier: 2`.

```json
{ "results": [
  { "target": "vndirect.com.vn", "allowed": true,
    "via": {"kind": "scope_target", "id": "…", "pattern": "*.vndirect.com.vn", "proof": "asserted"},
    "zone": null },
  { "target": "promo-landing.net", "allowed": false,
    "code": "no_entry",
    "message": "No scope entry, seed or verified domain covers this name.",
    "rule": null,
    "fixes": [
      {"action": "allow_temporarily", "pattern": "promo-landing.net", "target_type": "domain", "days": 7},
      {"action": "add_entry", "pattern": "*.promo-landing.net", "target_type": "domain"}
    ] }
] }
```

`via.kind`: `scope_target`, `seed`, `verified_domain`, or `internal` (a
private target routed by its zone, or a target no authority needs to cover).
`via.proof`: `verified` or `asserted`. `zone` is set for zone-routed
targets. `rule` names the caller's own rule that refused: `{"kind":
"exclusion"|"scope_target"|"tombstone"|"asset", "id", "pattern"}`; for
platform policy it is `{"kind": "platform_policy"}` with no detail.

### 6.5 Refusal codes

| Code | Meaning | Fixes offered |
|---|---|---|
| `invalid_target` | malformed, loopback, link-local, metadata, private outside a zone | — |
| `deny_list` | platform policy (§8.2) | `contact_support` |
| `excluded` | an active exclusion matches | `remove_exclusion` (approver) |
| `rejected` | the tenant rejected this name or a parent | `review_asset` |
| `needs_review`, `candidate`, `monitor_only` | attribution not confirmed | `review_asset` |
| `dependency` | the tenant's name on third-party infrastructure | `review_asset` |
| `no_entry` | nothing covers it | `add_entry`, `allow_temporarily` (approver), `request_access` (member) |
| `entry_pending` | covered only by an entry awaiting approval | `approve_entry` (approver) |
| `entry_expired` | covered only by an expired entry | `renew_entry`, `request_access` |
| `entry_inactive` | covered only by a deactivated entry | `activate_entry` |
| `tier_exceeds` | covering entries allow a lower tier | `raise_tier` (approver) |
| `proof_required` | platform sensors, `all`, or T2 need a verified root | `verify_domain`, `use_tenant_sensor` |
| `out_of_data_scope` | asset outside the actor's data scope | — |
| `not_an_asset` | a restricted member typed free text | `request_access` |
| `zone_none`, `zone_no_sensor`, `zone_sensor_mismatch` | scan-zone routing | `add_zone` |

Fix objects: `{"action", "pattern"?, "target_type"?, "days"?, "id"?,
"domain"?, "tier"?, "requires"?}`; `requires` is the permission the action
needs. A `tier_exceeds` refusal offers `raise_tier` with the `id` of the
caller's covering entry with the highest ceiling and the `tier` the probe
needs; when only a seed or verified domain covers the target (T1 at most),
`allow_temporarily` at that `tier` instead. The
dry run keeps only the fixes the caller may take (an approver gets
`allow_temporarily`, a member `request_access`, never both).

The same `code` (and `fixes`) appear on every refusal the API returns:
`TARGET_OUT_OF_SCOPE` errors list `details.refused[]` as
`{target, code, message, fixes}`, and dispatch-gate refusals carry `code`.

### 6.6 Review queue and inventory membership (existing routes, extended)

The review queue already exists (RFC-036 §6.10); the web uses it as the
"pending" list. Nothing new is built next to it.

- **`GET /api/v1/easm/candidates`** (`assets:read`, data-scoped):
  `states` (default `needs_review,candidate`), `types`, `min_confidence`,
  `search`, `reason` (new: a rule, e.g. `fqdn_under_asserted_root`), `page`,
  `per_page` ≤ 100. Each item: `asset_id`, `name`, `type`, `state`,
  `confidence`, `reason`, `human_decided`, `evidence[]` (`rule`, `technique`,
  `source`, `weight`, `observed`, `first_observed_at`, `last_observed_at`),
  and `covered_by` (new: the caller's scope entry, seed or verified domain
  that covers the name, or null; a null `covered_by` on approval means
  widening, so the UI offers "add scope entry" first). Evidence from a sensor
  (`source: "sensor:<id>"`) carries `source_label` and
  `observed.sensor_name`: the caller's own sensor's name, `platform sensor`
  for a platform sensor, never another organization's sensor.

  **Address rows** (an `ip_address`, or a service on an address) stay in
  review even when every name resolving to them is in scope: a name grant
  never becomes an IP grant (§4.3). Such a row explains itself:

  ```json
  { "name": "202.160.124.20", "type": "ip_address", "covered_by": null,
    "hint": "ip_needs_ip_entry",
    "resolved_from": ["vndirect.com.vn", "www.vndirect.com.vn"],
    "network": {"asn": "AS131386", "org": "VNDIRECT Securities Corporation",
                "shared": false, "org_matches": true},
    "fixes": [
      {"action": "add_entry", "target_type": "ip_address", "pattern": "202.160.124.20",
       "requires": "attack_surface:scope:approve"},
      {"action": "add_entry", "target_type": "cidr", "pattern": "202.160.124.0/24",
       "requires": "attack_surface:scope:approve"}] }
  ```

  - `resolved_from`: the caller's in-scope names with a `resolves_to` edge to
    the address (at most 10, within the caller's data scope).
  - `network`: the ASN and organization the inventory already holds (no
    lookup at request time); `shared` for CDN or cloud-provider space;
    `org_matches` when a distinctive word of the organization's name is in
    the ASN organization.
  - `fixes` go through `POST /scope/targets` (step-up, approvals, guardrails,
    audit). An approver gets "add this IP" and, only when `org_matches`, "add
    the /24 (IPv4) or /48 (IPv6) around it"; a member with `scope:write`
    gets `request_access` (a 7-day one-off for the address); anyone else
    none. Shared space gets no fix: those addresses serve other
    organizations. A covered row gets neither `hint` nor `fixes`.
- **`GET /api/v1/easm/summary`** (`assets:read`): `attribution` already
  counts `needs_review` and `candidate`; it adds `review_by_reason`
  (`{rule: count}`) for the caller's data scope. `surface` (by type), `new`
  and `exposed_services` count inventory members only (§4.4); exposures
  still count on review assets (a `subdomain_discovered` exposure is what
  sends a name to review).
- **`POST /api/v1/easm/candidates/decisions`** (`assets:write`, data-scoped,
  at most 200 assets, audited per asset): `{"asset_ids": […], "state":
  "confirmed"|"rejected"|"dependency"|"monitor_only"|"needs_review", "note":
  "…"}`. Unchanged, except that a confirmation no longer authorizes active
  probes by itself (§4.2).
- **`GET /api/v1/assets/{id}/attribution`**: adds `scope_status`
  (`in_scope`, `out_of_scope`, `internal` for zone-gated names,
  `not_applicable` for repositories and cloud resources) and `covered_by`
  (as above); `active_checks_allowed` / `active_checks_blocked_by` use the
  same gate, with `blocked_code` (a §6.5 code).
- **`GET /api/v1/attack-surface/stats`**: every count uses §4.4;
  `recent_changes[]` items add `asset_id`, `attribution_state`
  (`confirmed`, `needs_review`, `candidate`, `dependency`, `monitor_only`,
  `rejected`, or empty for a legacy asset) and `in_inventory` (bool).
- **`GET /api/v1/dashboard/stats`**: asset totals and breakdowns count
  inventory members only (§4.4).

### 6.7 Review by rule

The review queue can be worked a rule at a time: the platform groups pending
items into candidate scope entries, and the tenant accepts or rejects a whole
group. A rule **is** a scope entry or an exclusion, created through the same
paths as §6.1/§6.2; there is no second authority.

**`GET /api/v1/easm/candidates/suggestions`** (`assets:read`, data-scoped;
query `states` default `needs_review`, `limit` ≤ 50):

```json
{ "suggestions": [
  { "id": "domain:*.dev.ipas.com.vn",
    "kind": "domain_wildcard",
    "target_type": "domain",
    "pattern": "*.dev.ipas.com.vn",
    "strength": "strong",
    "covered": 12,
    "covered_sample": ["a.dev.ipas.com.vn", "b.dev.ipas.com.vn"],
    "blocked": 1,
    "blocked_sample": [{"name": "old.dev.ipas.com.vn", "code": "rejected"}],
    "hints": [
      {"kind": "discovering_seed", "value": "ipas.com.vn"},
      {"kind": "cert_org", "value": "IPAS JSC"},
      {"kind": "same_ns_as_verified", "value": "ns1.ipas.com.vn"}
    ] },
  { "id": "cidr:203.0.113.0/24", "kind": "ip_cidr", "target_type": "cidr",
    "pattern": "203.0.113.0/24", "strength": "medium", "covered": 5, "blocked": 0,
    "hints": [{"kind": "rdap_allocation", "value": "203.0.112.0/22 EXAMPLE-NET"}] }
  ],
  "individual": [
    { "asset_id": "…", "name": "104.16.1.2", "shared_ip": true,
      "reason": "shared or CDN provider address: accept one by one" }
  ] }
```

- **Domains:** a wildcard at each label level from the item up to the
  registrable domain (`*.dev.ipas.com.vn`, then `*.ipas.com.vn`), never at
  or above a public suffix (embedded PSL, §8.2), never a deny-listed name.
- **IPs:** the `/24` (IPv4) or `/48` (IPv6) around the items; the RDAP
  allocation or ASN only when our data already holds it (no new outbound
  call); never for shared, CDN or cloud-provider space (the asset's CDN flag
  or a known provider range): those items appear under `individual` with
  `shared_ip: true` and can only be accepted one by one. A suggested range
  larger than the §8.3 cap is not offered.
- **Counts:** `covered` = pending items the rule would confirm; `blocked` =
  items it covers that an exclusion, tombstone or rejected parent keeps out
  (they stay out; codes from §6.5).
- **Hints** are evidence we already hold: the root that discovered the names
  (`discovering_<origin>`: `easm_seed`, `scope_target`, `domain_asset`,
  `verified_domain`), a `verified_domain` or `seed` at or above the pattern,
  and the address's `asn` (number and organization). Certificate
  organizations, NS/SOA and RDAP allocations join when we store them (no new
  outbound call). Strength: `strong` with a verified domain, `medium` with a
  discovering root, seed or ASN, otherwise `weak`. Order: by strength, then
  from the most specific rule to the broadest, then by items covered. A
  broader pattern covering exactly the same items as a narrower one is
  dropped.
- **Shared space**: an address whose `cdn` property is set or whose ASN
  organization is a known CDN or cloud provider is never grouped.

**`POST /api/v1/easm/candidates/rules/preview`** and
**`POST /api/v1/easm/candidates/rules`**, same body:

```json
{ "action": "accept_rule",
  "target_type": "domain",
  "pattern": "*.dev.ipas.com.vn",
  "asset_ids": [],
  "reason": "Our dev environment (ticket OPS-12)" }
```

| `action` | Effect | Permission |
|---|---|---|
| `accept_rule` | creates a permanent scope entry for `pattern` exactly as `POST /scope/targets` does (step-up, §7 approvals, audit, admin notification; a caller without `scope:approve` creates a pending request). Once the entry is active, the pending items it covers are re-evaluated and confirmed through `matches_scope_target` (§4.3) | `scope:write` (+ step-up for approvers) |
| `accept_selected` | confirms only `asset_ids` (≤ 200, pending items of the caller only), like the decisions route; creates no entry, so active scanning still needs a covering entry (§4.2) | `assets:write` |
| `reject_rule` | creates a scope exclusion for `pattern` (the normal exclusion approval flow) and rejects the pending items it covers now (tombstones); future names it matches are rejected on arrival while the exclusion is in effect | `scope:write` + `assets:write` |

`target_type` is `domain`, `cidr`, `ip_range` or `ip_address`; a domain
rule never touches address items and the reverse. `reason` is required for
`accept_rule` and `reject_rule`. The preview (`assets:read`) returns exactly
what the action would change and changes nothing:

```json
{ "action": "accept_rule",
  "allowed": true,
  "refusal": null,
  "entry": {"target_type": "domain", "pattern": "*.dev.ipas.com.vn", "status": "pending", "approvals_required": 1},
  "would_confirm": [{"asset_id": "…", "name": "a.dev.ipas.com.vn"}],
  "would_reject": [],
  "stays_blocked": [{"asset_id": "…", "name": "old.dev.ipas.com.vn", "code": "rejected"}],
  "step_up_required": true }
```

`refusal` carries a §6.1 code (`PUBLIC_SUFFIX`, `DENY_LIST`,
`CIDR_TOO_LARGE`, `REQUEST_MUST_BE_ONE_OFF`, …) when the rule cannot be
created. The action route answers the same shape with `entry.id`, the
entry's actual `status`, and `confirmed` / `rejected` (the asset ids
changed). Every created entry, exclusion and decision is audited
(`via: review_rule`). Re-evaluation is idempotent (running it twice
changes nothing) and tenant-scoped; items outside the caller's data scope are
neither counted nor changed.

### 6.8 Coverage (`GET /stats`, `scope:read`)

`coverage` is the share of the **internet-facing inventory** that an active
scope target covers and no exclusion removes (research/53 SC8):

- the inventory is §4.4 (confirmed or unrecorded, `dependency`,
  `monitor_only`) of the stored types `domain`, `subdomain`, `ip_address`,
  `service` and `application`; repositories, cloud resources and the review
  queue are not in it;
- internal names (`localhost`, `.local`, `.internal`, `.lan`) and private,
  loopback, link-local and CGNAT addresses are counted apart
  (`inventory_internal`), on neither side: scan zones gate them;
- an asset matches on its host (the name, or the host of a URL or
  `host:port`) with the §4.1 rules; an IP exclusion wins on any overlap;
- everything is counted in one SQL statement over the **caller's data
  scope** (a restricted member counts only their assets; one with no scope
  rows counts nothing), so the numbers are not an oracle for the inventory
  outside it. A data scope that cannot be resolved fails the request.

```json
{ "total_targets": 7, "active_targets": 7, "total_exclusions": 3, "active_exclusions": 3,
  "coverage": 75.36,
  "inventory_internet_facing": 69, "inventory_in_scope": 52, "inventory_internal": 4 }
```

## 7. Approvals and notification (S3)

- Effective approvals: the tenant's `widening_approvals`, or
  `min(1, admins − 1)` when unset; at least 1 when the tenant has two or more
  admins; at least 1 for `t2`; capped at `admins − 1` only for the default.
- Approvers hold `scope:approve`, differ from the requester, and count once.
- Widening events notify every active owner and admin in-app and on the
  tenant's channels: entry created active, approved, activated, expiry
  extended, tier raised, exclusion removed or shortened, settings changed;
  a new request notifies the approvers.
- Audit actions: `scope_target.created|updated|activated|deactivated|deleted|
  approved|rejected|expired`, `scope_exclusion.*` (existing),
  `scope.settings_updated`.

## 8. Platform guardrails (S2), operator-level

None of these is a tenant setting; nothing a tenant sends turns them off.

### 8.1 Active-probe proof

`SCOPE_ACTIVE_PROOF`:

| Value | Rule |
|---|---|
| `off` | no proof needed (self-hosted default: the operator is the tenant) |
| `platform_sensors` | a job routed to platform sensors needs every target at or under a verified domain of the tenant (SaaS default) |
| `all` | every active probe needs a verified root (internal, zone-gated targets excepted) |

Unset: `platform_sensors` when `TENANT_CREATION_MODE=self_service`, else
`off`; any other value fails startup. Intrusive (T2) probes always need a
verified root. IP targets have no proof kind yet, so they are refused where
proof is required.

Where it is enforced:

- `platform_sensors` (and `all`): the scan trigger sends a job to platform
  sensors only when every target is at or under a verified domain. An
  explicit `sensor_preference=platform` with an unproven target is refused
  (`400 PROOF_REQUIRED`, the unproven targets named); `auto` keeps the job on
  tenant sensors.
- `all`: the ownership gate refuses an unproven internet target on every
  path (never-stored state `proof_required`, refusal code `proof_required`).
- Intrusive: scan create, quick scan and every single-scanner run refuse a
  scan whose tool only implements T2 stages (for example `zap`) when a target
  is unproven (`PROOF_REQUIRED`). A workflow scan checks proof per step: an
  intrusive step (its tool's tier is T2) is handed only the run's targets at
  or under a verified domain, and fails with `STEP_TARGETS_REFUSED` before any
  sensor sees it when none is left; its passive and active steps are not
  affected. An intrusive stage still never takes discovered targets
  (RFC-036).

### 8.2 Deny list and public suffixes

Checked when an entry is created or widened and again at dispatch:

- public suffixes (ICANN and private sections of the Public Suffix List,
  embedded through `golang.org/x/net/publicsuffix`, no network call): no entry
  may be, or wildcard, a public suffix (`*.com.vn`, `com`, `*.azurewebsites.net`);
- government and military suffixes (`gov`, `mil`, `gov.*`, `mil.*`,
  `gouv.fr`, `gc.ca`, `go.jp`, …);
- shared-provider apexes as wildcard roots (`*.amazonaws.com`,
  `*.cloudfront.net`, `*.herokuapp.com`, …); exact names under them stay
  allowed;
- `0.0.0.0/0`, `::/0`, link-local and cloud metadata addresses;
- the operator's own ranges and names, `SCOPE_DENY_EXTRA` (comma-separated
  domains and CIDRs; an entry that is neither fails startup).

A new entry that hits them is refused (`400 PUBLIC_SUFFIX`, `DENY_LIST`). At
dispatch the ownership gate refuses a deny-listed target on every path,
even inside the tenant's own scope target or after a person confirmed it
(never-stored state `platform_denied`, refusal code `deny_list`). The
refusal names no rule: "the platform does not allow this target".

### 8.3 CIDR caps

A public IPv4 range larger than `/SCOPE_MAX_PUBLIC_CIDR_V4` (default 16) or
IPv6 larger than `/SCOPE_MAX_PUBLIC_CIDR_V6` (default 32) is refused
(`400 CIDR_TOO_LARGE`), including `a-b` ranges by their size. Private ranges
are gated by zones and are not capped.

`GET /scope/settings` shows the operator's `active_proof` (read-only).

## 9. Rollout and upgrade

- One release, no flag. Changelog fragments describe each behaviour change.
- Existing entries keep working: they are `active`, permanent, `t1`, with
  `approved_at = created_at`.
- Assets confirmed on the Ownership tab but outside every entry, seed and
  verified domain stop being probed; runs say so in their warnings, and the
  refusal offers `add_entry`.
- Members who created scope targets directly now create requests.

## 10. Plan

| Phase | Items |
|---|---|
| P0 (this RFC) | S1 matcher; one authority check (I2/I3); expiring entries + requests + approvals + step-up + notification; settings; S4 rule; structured refusals + dry run; proof setting, deny list, PSL, CIDR caps |
| P1 | proof kinds (HTTP file, cloud connector, platform-reviewed LOA); seeds folded into scope entries; `commands.authorizing_entry_id`; platform deny list as a table with a console; velocity signals; sensor-local policy aligned with §4.1 |
| P2 | T2 grants with engagement labels; name-vs-IP grants in signed jobs; opt-out registry |

## 11. Implementation

| PR | Content |
|---|---|
| S1 | matcher, tests, docs, this RFC |
| Authority | one authority check for typed and inventory targets; Ownership-tab bypass removed |
| Guardrails | PSL, deny list, CIDR caps, `SCOPE_ACTIVE_PROOF` |
| Entries | migration `001198`, expiry, requests, approvals, step-up, notification, settings, sweep |
| Discovery | `matches_scope_target` + backfill |
| Review by rule | §6.7 suggestions, preview, accept/reject as a rule |
| Inventory | §4.4 one membership definition; `attribution_state` on recent changes; review counts by reason; `covered_by` on queue items |
| Refusals | codes, fixes, `POST /check` dry run |
| Tier ceilings | `max_tier` enforced at every dispatch (`tier_exceeds`, `raise_tier`); per-step proof for intrusive workflow steps |
