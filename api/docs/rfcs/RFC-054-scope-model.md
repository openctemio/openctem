# RFC-054: Scope model (what a tenant may actively probe)

| | |
|---|---|
| Status | Accepted (decisions S1–S6, 2026-10-07; S3 and S6 revised by A1–A5, 2026-10-09, §12; approvals limited to Strict scan governance by RFC-073, 2026-10-10, §13; flexible scope amendment 2026-10-11, §14: bulk add implemented; attack-surface decisions 2026-10-13, §14.5: R3 and R4 adopted and implemented, connector assets in scope by default, children follow their host; R5 awaiting owner decision; inventory first, scope later 2026-10-13, §15: state `discovered` and the review-gate setting implemented, triage and metrics toggle in progress; unclassified assets get low-impact checks behind platform guardrails 2026-10-14, §16: implemented; repository entries and CI trusts 2026-10-15, §17: implemented); P0 implemented |
| Scope | api (`pkg/domain/scope`, `internal/app/scope`, `internal/app/actscope`, `internal/app/easm`, `internal/app/scan`, `internal/app/certmonitor`, handlers, migrations), web (Scoping, scan dialog), sensor-local policy (follow-up) |
| Architecture | [active-probe-gate.md](../architecture/active-probe-gate.md) |
| Related | RFC-023 (zones), RFC-036 §6.3/§6.4 (ownership gate, attribution), RFC-040 §5.6 (widening approvals, amended here), RFC-042 §6.13 (wildcard semantics, superseded here), RFC-050 (data scope) |

## 1. Summary

Several records decide whether a target may be probed today: scope targets,
root-domain seeds, verified domains, attribution states and inventory
membership, with exclusions, scan zones and scan windows (RFC-067) on top. They
disagreed with each other, widening scope was one unaudited click, and a
refusal said nothing about how to fix it.

This RFC makes one model out of them:

1. **`*.x` means `x` and every name below it** (S1). An exclusion of exactly
   `x` carves the apex out.
2. **One authority check** decides for every target, typed or inventory, on
   every path. An asset's ownership record alone never authorizes an active
   probe; a scope entry must cover it. Seeds fold into entries and a verified
   domain is proof only (§6.1 "One concept").
3. **Names covered by a permanent scope entry are confirmed** into the
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
   (platform setting, §8.1), public-suffix refusal, a minimal platform deny list
   and CIDR size caps.
8. **Tenant settings** (S5): auto-join, who adds one-off targets, maximum
   days, approval count, default tier. There is **no** switch that turns
   scope off.

## 2. Threat model

| Actor | Goal | Control |
|---|---|---|
| Careless admin | types `example.org` for `example.com` | preview (`POST /scope/check`), step-up, second approver when the tenant has two or more admins, admin notification |
| Compromised admin session | adds `*.victim.example` and scans it | step-up on every widening route (a stolen cookie alone cannot widen), approvals, notification of every admin, audit |
| Malicious tenant (colluding admins) | uses the platform to scan a third party | approvals do not help; **ownership proof** for probes from platform sensors (platform setting, §8.1), platform deny list, public-suffix refusal, CIDR caps; none of them tenant-overridable |
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
| S2 | (a) proof for active probes is a platform setting (revised 2026-10-11, §8.1): default off; a public multi-tenant cloud turns it on, and then platform sensors and intrusive (T2) probes need proof |
| S3 | (a) widening approvals are a tenant setting 0/1/2, default `min(1, admins − 1)`, never 0 for T2 (amends RFC-040 Q2 (a)). Revised 2026-10-09 (§12): approvers are named and reminded; an owner with no other approver self-approves with a fresh authenticator code; a platform policy may make approvals tenant-controlled or off |
| S4 | yes, refined 2026-10-07: an active, non-expiring scope entry or seed confirms the names it covers (`matches_scope_target`, no review); IPs only through IP entries; one-off entries never confirm; tombstones and exclusions win; removal keeps the asset and stops scanning; backfill of existing `needs_review` rows |
| S5 | tenant knobs (§7); no global scope-off switch, ever |
| S6 | one-off = a scope entry with `expires_at` + `reason`; admins create, members request; default 7 days, max 30. Revised 2026-10-09 (§12): T2 entries have an owner-set maximum (7/30/90/365 days or permanent, default 30) and long ones are re-attested every 90 days or downgraded to T1 |

## 4. Semantics

### 4.1 Domain patterns

| Pattern | Covers |
|---|---|
| `x` | exactly `x` |
| `*.x` (and `**.x`) | `x` and every name below it, at any depth |
| `*.x` + exclusion `x` | the subdomains of `x`, not `x` |

Matching is case-insensitive, ignores one trailing dot and compares IDNA ASCII
forms. Scope targets and exclusions use the same matcher
(`pkg/domain/scope.matchDomain`), and so do verified domains (proof) and the
active-scan gate.

**Upgrade note.** Existing `*.x` scope targets start covering their apex, and
existing `*.x` exclusions start excluding it. A tenant that needs the
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
   entry (approved, unexpired) with `max_tier` at or above the probe's tier.
   Nothing else authorizes: a verified domain of any purpose is proof only
   (step 7), and root-domain seeds are entries since migration `001262`. A
   target covered only below the probe's tier is refused `tier_exceeds`. The
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
confirmation alone never authorizes: a scope entry must cover the name. Since
§14.5 (R3) a person's confirmation of a domain, subdomain or public address
adds that exact entry through the scope service while scan approval is Off or
On and the organization's `confirm_adds_to_scope` setting is on; under Strict,
or with the setting off, confirmation records ownership only and the refusal
offers "add scope entry".

### 4.3 Discovered names (S4, refined 2026-10-07)

A declared, permanent scope entry is an intentional ownership claim, made with
step-up and approval (§6.1, §7). So:

- **Rule `matches_scope_target`** (strong, weight 0.99): a domain name that a
  tenant **active, non-expiring** domain scope target covers (`x`, or `*.x` /
  `**.x` under §4.1) is
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

**When the join runs.** After every committed change that can confirm a
waiting name, from the scope service (so the API, review rules and later
automations all get it):

- an entry comes into effect: created in effect, **approved** (the usual path
  for a new wildcard, since widening needs approval), activated;
- an entry in effect changes (pattern, type, expiry, tier, discovery);
- an exclusion goes away or shrinks: deleted, taken out of effect, shortened,
  or its testing mode changed.

A pending entry or request, a rejection and a new exclusion confirm nothing
and ask for nothing. The runs are debounced per tenant (2 s) and serialized
(never two joins of one tenant at once; a change during a run gets one more
run). The `scope-join` controller repeats every tenant every 6 h as the
safety net (it also picks up exclusions that expire).

**Feedback.** `POST /scope/targets/preview` `{target_type, pattern}` answers
`{would_confirm}`: the names waiting for review the entry would confirm if it
were permanent and in effect. A change that put an entry into effect or
changed one in effect (create, approve, activate, update) runs the join at
once and answers `join: {confirmed_count, assets_filter: {covered_by}}`;
`GET /assets?covered_by=<entry id>` lists the assets the join confirmed
through that entry. Both counts cover only the assets the caller may see
(Layer 2 data scope); without the data scope the count is refused. Each run
that confirms names writes one system audit event
`asset.attribution_auto_confirmed` (count and up to 50 names).

**When the entry goes away** (deleted, deactivated, narrowed or expired): the
asset, its history and findings stay; nothing is deleted. Active scanning stops
at once, because the authority check (§4.2 step 6) no longer finds a cover;
the asset's attribution view answers `scope_status: "out_of_scope"` and the
refusal code `no_entry`.

**Backfill.** A one-shot job re-evaluates the records that are `needs_review`
(for example reason `fqdn_under_asserted_root`) and not human-decided: each
name now covered by an active, non-expiring scope target
of the **same tenant** (and not excluded, not tombstoned, not under a rejected
name, `auto_join_discovered` on) gets the `matches_scope_target` evidence and
is re-evaluated, which confirms it. Idempotent (evidence upserted per asset,
rule and source; confirmed records are left alone), per tenant, one system
audit event per tenant (`attribution.backfill_confirmed`, the count and up to
50 names). It runs at API start-up, recorded once per tenant.

Tests: a wildcard match confirms; an expiring entry does not; an IP does not
(unless inside an IP scope entry); an exclusion or tombstone blocks; removing
the entry flags the asset out of scope and stops active checks; another
tenant's entries have no effect.

### 4.4 Inventory membership (one definition)

Amended by §15: `discovered` is in the inventory too, and metrics count the
attributed inventory.

An asset is **in the inventory** when its attribution is confirmed (recorded,
or no record: a legacy asset), `discovered`, `dependency` or `monitor_only`
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
  "created_by": {"kind": "user", "id": "…", "name": "Jane Doe"},
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
{ "kind": "user", "id": "019d…", "name": "Jane Doe" }
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

**One concept: scope entries** (migration `001262`).
Seeds are folded into entries and `/api/v1/easm/seeds` is removed: a root
domain to discover from is the permanent entry `*.example.com` with
`discovery` on, created like any entry (approvers, step-up, approvals,
guardrails, notification, audit). Each `root_domain` seed became `*.v`
(`origin: seed_migration`, `t1`, active, no approvals) unless an active
permanent wildcard entry already covered it; an exact `*.v` entry took the
seed's discovery and at least `t1`, and one that did not authorize was put
back into effect (the seed authorized it). Each `easm`-purpose verified
domain that no entry covered became `*.d` the same way. A domain verified
for SSO sign-in got no entry. After this, **only entries authorize**; a
verified domain (any purpose) is proof only and puts `proof: verified` on
every entry at or under it.

`discovery` (bool, default true) on create and update, and in every
response: names under the entry are discovered (Certificate Transparency,
DNS checks) and join the inventory (§4.3). It runs only for a permanent
domain entry: a one-off or non-domain entry never discovers. Turning it on
widens what is discovered: `scope:approve` and step-up, every administrator
notified; it does not send the entry back for approval (discovery is
passive). Turning it off narrows. An entry that comes into effect with
discovery on starts a discovery sweep at once.

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

**Path exclusions (RFC-056 §5, migration `001290`).** An exclusion of type
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
{ "targets": ["example.com", "promo.example.net"],
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
  { "target": "example.com", "allowed": true,
    "via": {"kind": "scope_target", "id": "…", "pattern": "*.example.com", "proof": "asserted"},
    "zone": null },
  { "target": "promo.example.net", "allowed": false,
    "code": "no_entry",
    "message": "No scope entry covers this name.",
    "rule": null,
    "fixes": [
      {"action": "allow_temporarily", "pattern": "promo.example.net", "target_type": "domain", "days": 7},
      {"action": "add_entry", "pattern": "*.promo.example.net", "target_type": "domain"}
    ] }
] }
```

`via.kind`: `scope_target`, or `internal` (a
private target routed by its zone, or a target no authority needs to cover).
`via.proof`: `verified` or `asserted`. `zone` is set for zone-routed
targets. `rule` names the caller's own rule that refused: `{"kind":
"exclusion"|"scope_target"|"tombstone"|"asset", "id", "pattern"}`; for
platform policy it is `{"kind": "platform_policy"}` with no detail.

**Where the scan would run** (`routing`, 2026-10-11). The response also
says where a scan of these targets would run, decided as the trigger decides:
`{"preference": "auto"|"tenant"|"platform", "runs_on": "tenant"|"platform"|"waits",
"reason", "sensor": {"id", "name"}}`. Reasons: `platform_needs_proof` (auto,
proof required by the platform setting of §8.1, and some targets unproven:
the job runs on the organization's own sensor), `tenant_first`, `tenant_busy`,
`internal_targets`, `no_tenant_sensor`, `platform_sensors`. `sensor` names
only the organization's own sensor; a platform sensor is never named. With
the proof setting on, auto refuses an unproven target (`proof_required`) only
when no own sensor can take the job; intrusive probes need proof on any
sensor, and their `proof_required` refusal does not offer "use your own
sensor".

**Resolved address** (`resolved`). A `zone_none` refusal of a hostname that
resolves to a private address lists those addresses (at most 8), so the
Review can say "resolves to 10.x.x.x, an internal address". It is shown only
when the answer cannot come from the platform's own internal DNS: zone
routing resolves through a public resolver (`SCAN_ZONE_RESOLVER`), or
organizations are not self-service.

**Skip the refused targets** (`skip_refused_targets` on `POST /scans`). The
creator may save a scan with only the targets this check allows now: the
create runs the same dry run, leaves the refused targets out and records
them with their codes in `scans.skipped_targets` (shown on the scan) and in
every run's context (`skipped_targets`, never sent to a sensor). The kept
targets then pass every normal create check, so nothing the gate refuses is
saved or scanned; with no target left the create is refused
(`NO_ALLOWED_TARGETS`).

### 6.5 Refusal codes

| Code | Meaning | Fixes offered |
|---|---|---|
| `invalid_target` | malformed, loopback, link-local, metadata, private outside a zone | — |
| `deny_list` | platform policy (§8.2) | `contact_support` |
| `excluded` | an active exclusion matches | `remove_exclusion` (approver) |
| `rejected` | the tenant rejected this name or a parent | `review_asset` |
| `needs_review`, `candidate`, `monitor_only` | attribution not confirmed (an automatic `needs_review` or `candidate` record is lifted by an active entry that covers the name, §14.5) | `review_asset` |
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
| `unresolved` | a hostname with no DNS answer from the platform, so zone routing cannot place it | — (fix the DNS record or scan its address) |

Fix objects: `{"action", "pattern"?, "target_type"?, "days"?, "id"?,
"domain"?, "tier"?, "requires"?}`; `requires` is the permission the action
needs. A `tier_exceeds` refusal offers `raise_tier` with the `id` of the
caller's covering entry with the highest ceiling and the `tier` the probe
needs. The
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
  and `covered_by` (new: the caller's scope entry
  that covers the name, or null; a null `covered_by` on approval means
  widening, so the UI offers "add scope entry" first). Evidence from a sensor
  (`source: "sensor:<id>"`) carries `source_label` and
  `observed.sensor_name`: the caller's own sensor's name, `platform sensor`
  for a platform sensor, never another organization's sensor.

  **Address rows** (an `ip_address`, or a service on an address) stay in
  review even when every name resolving to them is in scope: a name grant
  never becomes an IP grant (§4.3). Such a row explains itself:

  ```json
  { "name": "203.0.113.20", "type": "ip_address", "covered_by": null,
    "hint": "ip_needs_ip_entry",
    "resolved_from": ["example.com", "www.example.com"],
    "network": {"asn": "AS64500", "org": "Example Org",
                "shared": false, "org_matches": true},
    "fixes": [
      {"action": "add_entry", "target_type": "ip_address", "pattern": "203.0.113.20",
       "requires": "attack_surface:scope:approve"},
      {"action": "add_entry", "target_type": "cidr", "pattern": "203.0.113.0/24",
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
  { "id": "domain:*.dev.example.org",
    "kind": "domain_wildcard",
    "target_type": "domain",
    "pattern": "*.dev.example.org",
    "strength": "strong",
    "covered": 12,
    "covered_sample": ["a.dev.example.org", "b.dev.example.org"],
    "blocked": 1,
    "blocked_sample": [{"name": "old.dev.example.org", "code": "rejected"}],
    "hints": [
      {"kind": "discovering_scope_target", "value": "example.org"},
      {"kind": "cert_org", "value": "Example Org"},
      {"kind": "same_ns_as_verified", "value": "ns1.example.org"}
    ] },
  { "id": "cidr:203.0.113.0/24", "kind": "ip_cidr", "target_type": "cidr",
    "pattern": "203.0.113.0/24", "strength": "medium", "covered": 5, "blocked": 0,
    "hints": [{"kind": "rdap_allocation", "value": "203.0.112.0/22 EXAMPLE-NET"}] }
  ],
  "individual": [
    { "asset_id": "…", "name": "198.51.100.2", "shared_ip": true,
      "reason": "shared or CDN provider address: accept one by one" }
  ] }
```

- **Domains:** a wildcard at each label level from the item up to the
  registrable domain (`*.dev.example.org`, then `*.example.org`), never at
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
  (`discovering_<origin>`: `scope_target`, `domain_asset`,
  `verified_domain`), a `verified_domain` at or above the pattern,
  and the address's `asn` (number and organization). Certificate
  organizations, NS/SOA and RDAP allocations join when we store them (no new
  outbound call). Strength: `strong` with a verified domain, `medium` with a
  discovering root or ASN, otherwise `weak`. Order: by strength, then
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
  "pattern": "*.dev.example.org",
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
  "entry": {"target_type": "domain", "pattern": "*.dev.example.org", "status": "pending", "approvals_required": 1},
  "would_confirm": [{"asset_id": "…", "name": "a.dev.example.org"}],
  "would_reject": [],
  "stays_blocked": [{"asset_id": "…", "name": "old.dev.example.org", "code": "rejected"}],
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
scope target covers and no exclusion removes:

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
  A pending entry names them (§12.2); an owner with no other approver may
  approve their own entry with a fresh authenticator code (§12.3).
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

A platform setting, edited by a super admin in Console > System > Platform
scanning: **"Require a verified domain before platform sensors scan a
target"** (`platform_settings` key `platform_sensor_proof`). The former
environment variable `SCOPE_ACTIVE_PROOF` is retired: startup refuses it with
a hint (owner decision 2026-10-11, revising S2).

| Setting | Rule |
|---|---|
| off (default) | no proof needed anywhere: assets come from many sources, and the organization's scope entry is the authorization. The scope gate, exclusions, the deny list (§8.2), scan zones for private addresses and tier ceilings stay in force |
| on | a job routed to platform sensors needs every target at or under a verified domain of the tenant, and intrusive (T2) probes need one on any sensor |

A public multi-tenant cloud should turn it on: platform sensors send packets
from the operator's addresses, and only ownership proof stops a tenant from
pointing them at a third party. A self-hosted operator runs its own
infrastructure and usually leaves it off. A change needs super_admin, a fresh
console authenticator code and a reason; it is written to the admin audit log
at critical severity (`platform.platform_sensor_proof_changed`) and the other
platform administrators are emailed. An unreadable stored value counts as on
(fail closed); a value never stored is the default, off. Replicas cache the
value for 15 seconds. IP targets have no proof kind yet, so they are refused
where proof is required.

Where it is enforced when on:

- the scan trigger sends a job to platform sensors only when every target is
  at or under a verified domain. An explicit `sensor_preference=platform`
  with an unproven target is refused (`400 PROOF_REQUIRED`, the unproven
  targets named); `auto` keeps the job on the tenant's own sensors, and the
  scope check (`POST /scope/check`) says so.
- Intrusive (setting on): scan create, quick scan and every single-scanner run refuse a
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
- Assets confirmed on the Ownership tab but outside every entry stop being
  probed; runs say so in their warnings, and the
  refusal offers `add_entry`.
- Members who created scope targets directly now create requests.

## 10. Plan

| Phase | Items |
|---|---|
| P0 (this RFC) | S1 matcher; seeds folded into entries and verified domains proof only; one authority check (I2/I3); expiring entries + requests + approvals + step-up + notification; settings; S4 rule; structured refusals + dry run; proof setting, deny list, PSL, CIDR caps |
| P1 | proof kinds (HTTP file, cloud connector, platform-reviewed LOA); `commands.authorizing_entry_id`; platform deny list as a table with a console; velocity signals; sensor-local policy aligned with §4.1 |
| P2 | T2 grants with engagement labels; name-vs-IP grants in signed jobs; opt-out registry |

## 11. Implementation

| PR | Content |
|---|---|
| S1 | matcher, tests, docs, this RFC |
| Authority | one authority check for typed and inventory targets; Ownership-tab bypass removed |
| Guardrails | PSL, deny list, CIDR caps, platform sensor proof setting |
| Entries | migration `001198`, expiry, requests, approvals, step-up, notification, settings, sweep |
| Discovery | `matches_scope_target` + backfill |
| Review by rule | §6.7 suggestions, preview, accept/reject as a rule |
| Inventory | §4.4 one membership definition; `attribution_state` on recent changes; review counts by reason; `covered_by` on queue items |
| Refusals | codes, fixes, `POST /check` dry run |
| Tier ceilings | `max_tier` enforced at every dispatch (`tier_exceeds`, `raise_tier`); per-step proof for intrusive workflow steps |

## 12. Amendment 2026-10-09: approvers, long intrusive grants, platform policy

Owner feedback on the P0: "Who is the other approver? I'm an admin." and
"This time limit is too tight; sometimes it must be open permanently, not
everyone has time to come back every 7 days." Then: "the platform admin side
should have a function to turn this approval requirement on/off." Decisions
A1–A5 (owner, 2026-10-09) revise S3 and S6.

### 12.1 Threat model of the revision

| Risk | Control |
|---|---|
| A pending entry waits forever because nobody knows who approves | the entry names its approvers and the approvals it still needs; they are notified in-app, by email and on the organization's channels, and anyone with `scope:write` may remind them (once an hour per entry) |
| A single-owner organization cannot use T2 at all (S3 says T2 never needs 0 approvals, and there is no second person) | the owner approves their own entry, only when no other approver exists, with a fresh authenticator code and a reason; high-severity audit, every administrator and the channels told. Never automatic |
| A stolen session self-approves | a session cookie or a recent sign-in is not enough: the code must come from the owner's authenticator app in the same request, and a used code cannot be replayed |
| A forgotten permanent intrusive grant keeps authorizing T2 probes for years | re-attestation (§12.5): every 90 days (30–180) an owner or administrator confirms "keep T2"; without an answer within 14 days the entry is downgraded to T1 (never deleted), with notification and audit |
| A long intrusive grant set by an administrator against the owner's intent | the T2 maximum duration is an owner-only setting (step-up, audit, every administrator told) |
| An operator relaxes approvals for a tenant silently | the platform approval policy (§12.6) is a platform administrator's explicit choice: super_admin, fresh console TOTP code, reason, critical admin audit, the other platform administrators and the tenant's administrators told |
| Relaxed approvals become "scope off" | they do not: step-up on every widening, the dry run, ownership proof for T2 and platform sensors, the platform deny list, public-suffix refusal, CIDR caps, audit and notification of every tenant administrator all stay. Only the second person is relaxed |

Approvals protect against a typo and against a single stolen session. They
do not protect against an organization that wants to scan a third party
(colluding administrators approve each other): ownership proof and the
platform guardrails do (§2). Relaxing approvals is therefore an operator's
explicit, audited choice, never a tenant's.

### 12.2 A1: name the approvers

Approvers of a scope entry are the organization's active members (active
account, unexpired membership) whose role is owner or admin, or who hold
`attack_surface:scope:approve` through a role. A pending entry's response
carries:

```json
"approval": {
  "remaining": 1,
  "eligible_approver_count": 2,
  "eligible_approvers": [{"kind": "user", "id": "…", "name": "Adam"}],
  "self_approval_available": false,
  "reminded_at": "…", "can_remind_at": "…"
}
```

- `eligible_approvers` excludes the requester and anyone who already
  approved. Names are returned only to a caller who may see the members
  (`team:members:read`); everyone else gets the count. No email is ever
  returned.
- A new pending entry notifies every administrator in-app, every eligible
  approver in-app and by email, and the channels (`approval_requested`).
- **`POST /scope/targets/{id}/remind`** (`scope:write`): the same request
  again to the eligible approvers. At most once per hour per entry, checked
  atomically in the database (`429 REMINDER_TOO_SOON`). Audited
  (`scope_target.approvers_reminded`).
- The email links to the Scope page and carries no capability: sign-in and
  the approval permission authorize, so a forwarded email grants nothing.

### 12.3 A2: an owner without another approver

**`POST /scope/targets/{id}/self-approve`** (`scope:approve`)
`{"reason": "…", "totp_code": "123456"}` puts the caller's own pending entry
into effect when all of these hold, else `403 SELF_APPROVAL_NOT_ALLOWED`:

- the caller requested the entry (created or last widened it);
- the caller is an owner of the organization (read from the membership, not
  the token);
- the eligible approvers cannot give the remaining approvals (in practice:
  nobody else can approve).

The code must come from the caller's authenticator app in this request
(`SELF_APPROVAL_NEEDS_TOTP` without one, `SELF_APPROVAL_INVALID_CODE` for a
wrong or reused code; a wrong code counts towards the lockout). A password or
an open step-up window is not enough. The approval row records
`self_approved` and the reason (migration `001615`); the audit event
`scope_target.self_approved` is high severity; every administrator and the
channels (`security_alert`) are told. S3 is unchanged in substance: a T2
entry still needs one approval, which here is the owner's own, proven with
the second factor.

### 12.4 A3: the T2 maximum duration

S6 bounded every expiring entry by `one_off_max_days` (1–30, default 7), and
T2 entries had to expire. Revised: T2 entries have their own bound, the
owner-only setting `t2_max_duration`: `7d`, `30d` (default), `90d`, `365d` or
`permanent`. **`PUT /scope/settings/intrusive`** (`scope:approve`, owner
role, step-up) `{"t2_max_duration": "90d", "reason": "…"}` changes it:
high-severity `scope.settings_updated` with the reason, every administrator
told. `PUT /scope/settings` never changes it. `GET /scope/settings` adds
`t2_max_duration`, `t2_max_days` (the most `expires_in_days` a t2 entry may
ask for; 365 when permanent is allowed) and `t2_permanent_allowed`. The
bound is enforced on create, on update and when only the tier is raised
(`400 INTRUSIVE_TOO_LONG`; `INTRUSIVE_NEEDS_EXPIRY` for a permanent t2 entry
when not allowed). The one-off policy (`one_off_targets: disabled`) does
not apply to t2 expiries. Lowering the bound does not shorten existing
entries; attestation (§12.5) covers the long ones. A T2 entry still needs a verified domain for its probes (§8.1)
and one approval at creation and on every widening. T0/T1 one-off entries
keep `one_off_max_days`; T0/T1 entries may still be permanent.

### 12.5 A4: re-attestation instead of re-review

An active T2 entry whose life runs past its next attestation (permanent, or
expiring after it) is attested every `t2_attestation_days` (30–180, default
90, owner-only) from its approval or last attestation:

1. when an attestation falls due, the owners and administrators are asked
   "Keep T2 for `<pattern>`?" (in-app, email, channels);
2. **`POST /scope/targets/{id}/attest`** (`scope:approve`) confirms it and
   starts the next period. One click, sign-in required; the link carries no
   capability;
3. without a confirmation within 14 days the attestation job downgrades the
   entry to T1 (never deletes it): system audit
   `scope_target.t2_downgraded`, every administrator and the channels told.
   The job is idempotent (it only changes T2 entries that are overdue).
   Raising the entry back to T2 is an ordinary widening (step-up, approval).

Implementation: migration `001620` adds `attested_at`, `attested_by` and
`attestation_requested_at` to `scope_targets`. The `scope-attestation`
controller runs hourly (`scope.Service.ReconcileAttestations`); every write
is tenant-scoped and conditional (a request opens only when none is open; the
downgrade happens only while the request it saw is still open), so a rerun,
a second replica or a concurrent confirmation never downgrades a confirmed
entry. A request is audited as `scope_target.attestation_requested`, a
confirmation as `scope_target.attested`. An active T2 entry's response
carries `attestation: {due_at, requested_at, downgrade_at, attested_at,
attested_by}`; the web lists due entries on the Approvals tab with "Keep T2".
`t2_attestation_days` is part of the owner-only `PUT
/scope/settings/intrusive`. An existing T2 entry's first period starts at its
approval.

### 12.6 A5: platform policy for widening approvals

A platform administrator sets, as a platform default and per organization
(an override), how widening approvals work:

| Mode | Effect |
|---|---|
| `required` (default) | §7 as amended: the tenant's 0/1/2, at least 1 with two or more administrators and for T2 |
| `tenant_controlled` | the organization's owner may set 0, 1 or 2 for every tier, T2 included |
| `disabled` | no approvals for any tier; a member's request still needs an approver |

`GET/PUT /api/v1/admin/settings/scope-policy` (platform default) and
`GET/PUT /api/v1/admin/tenants/{tenantId}/scope-policy` (override; `null`
inherits). Reads: any platform administrator. Changes: super_admin, a fresh
console TOTP code and a reason; critical admin audit; the other platform
administrators emailed; the organization's administrators told in-app. No
tenant route can read the override's audit trail or change it. The tenant's
`GET /scope/settings` shows the effective mode and its source, and the web
says "Approvals disabled by your platform administrator" or "Your
organization requires N approvals"; the widening warning adapts.

### 12.7 Implementation

| PR | Content |
|---|---|
| Approvers | A1, A2: approver directory, `approval` on pending entries, notify and remind, self-approval with a fresh authenticator code (migration `001615`) |
| T2 duration | A3: `t2_max_duration`, owner-only `PUT /scope/settings/intrusive`, server-side bound, entry dialogs |
| Attestation | A4: attestation timestamps, `POST /attest`, the attestation and downgrade job |
| Platform policy | A5: platform default and per-organization override, console section, effective policy on the tenant settings |
| Start when approved | §12.8: a scan saved to start once the pending entries covering its targets are approved (migration `001727`) |

**Job signer ledger** (RFC-040 §5.6). Every write above goes through the
scope ledger hook (`scope.Service.commitEntry`): an owner's own approval is
sent with the approval marked `self_approved` before it is saved (a refusal
saves nothing); a confirmation (`/attest`) changes nothing the ledger holds;
the T2 → T1 downgrade is a narrowing, saved with its conditional update and
then sent; every widening carries `platform_policy` (the A5 mode in force).
The reminder and attestation-request timestamps are the only scope writes
outside the hook: they change nothing that authorizes probes (listed in the
ledger guard with that reason).

### 12.8 Start a scan when its scope is approved

A requester who pastes a target that only a pending entry covers would
otherwise have to come back after the approval and build the scan again.
`POST /scans` takes `start_when_scope_approved`: when every direct target the
ownership gate refuses is covered by a pending entry of the tenant (the
explainer answers `entry_pending`), the scan is saved without a run and a row
in `scan_scope_waits` records who asked. Any other refusal (no entry, a
rejected asset, the deny list) still refuses the request; the act-scope,
tier and proof checks of the create run as usual. The response says
`starts_when_scope_approved`.

When an entry of the tenant comes into effect (created active, approved,
self-approved or activated), the waiting scans whose targets now all pass
the ownership gate are claimed (the row is deleted, so a scan starts once)
and triggered as the person who asked. The trigger runs every gate again
(act scope of that person, ownership, tier, proof, zones, freeze windows) and
skips anything refused with a run warning; a paused or disabled scan does
not start. A scan still refused keeps waiting; one run by hand since it was
saved stops waiting; a wait lapses after 30 days.

Threat model: the wait authorizes nothing. Only the approval of the entry,
under the approval rules above, puts the targets in scope, and the start is
checked as if the person who asked had pressed Run then. Waits are
tenant-scoped (every query carries the tenant; a wait can only name the
tenant's own scan) and removed with their scan.

## 13. Amendment 2026-10-10: approvals follow scan governance

Owner decision: approvals are opt-in and approve scans, not scope entries
([RFC-073](RFC-073-scan-approval-governance.md)). The S3 approvals of §7
and the sole-owner self-approval of §12.3 apply only when the organization's
scan approval is **Strict**; in Off (default) and On a widening needs no
second person. The platform policy of §12.6 now governs scan approval
(`tenant_controlled`, `off`, `on`, `strict`; RFC-073 §5); its
`tenant_controlled` owner-only approval count is removed. Unchanged in every
mode: step-up on widening routes, the dry run, the
T2 maximum duration and re-attestation (§12.4, §12.5), ownership proof, the
platform deny list, CIDR caps, audit and notification.

Amended 2026-10-11 (owner decision 2026-10-10: "approval only when creating
scans, not for scope assets"): member requests (§6.1) and the exclusion
review of §6.2 also apply only in Strict. In Off and On a caller with
`attack_surface:scope:write` adds or widens an entry directly (step-up kept)
and an exclusion is in effect at once; rows left pending stay pending and
reviewable. Details in RFC-073 §6.


## 14. Amendment 2026-10-11: flexible scope

Owner request: scope must be as flexible as possible without becoming unsafe.
After RFC-073 the policy friction is gone outside Strict (no approvals, no
member requests, no tier ceilings); what is left is mechanical: entries are
added one pattern at a time, assets that arrive by import, connector or CI
are blocked until someone adds them by hand, addresses behind in-scope names
need their own entries, and private targets need a scan zone first.

One authority stays: scope entries and exclusions. Every relaxation either
creates entries through `scope.Service` (so the job signer accepts each
widening before it is saved, and audit and notification follow), or reads a
fact the signer already shares. There is no implicit authority from inventory
state at dispatch time, no automatic address inheritance and no switch that
turns scope off.

### 14.1 Rules

| # | Rule | Before | After | State |
|---|---|---|---|---|
| R1 | Add many entries | one pattern per request; one notice to every administrator per entry | `POST /scope/targets/bulk` (≤ 200 items): step-up once before any write, each item an ordinary create, a result per item, one notice for the batch | implemented |
| R2 | Add from anywhere | one asset's ownership section, the review queue, a scan refusal | inventory selection → "Add to scope" (exact entries), the scan wizard's "add the missing targets" and finding actions use R1 | inventory: implemented; others follow |
| R3 | A person confirms an asset | confirmation records ownership only (§4.2) | the tenant setting `confirm_adds_to_scope` (default on; Off and On only, Strict keeps ownership only) creates the exact entry when a person confirms; automated sources never do (§14.5) | adopted 2026-10-11, implemented |
| R4 | Addresses behind in-scope names | never inherit (S4) | one grouped suggestion card of the addresses in-scope names resolve to (`GET /easm/suggestions`); shared addresses (CDN record, provider network, published CDN edge ranges, 3+ registrable domains, another organization's network) are listed apart and never offered; an unknown network is said, never implied safe; never automatic (§14.5) | adopted 2026-10-11, implemented |
| R5 | Private targets on the organization's own sensor | refused without a scan zone (`zone_none`) | proposed: allowed when the scan runs on a tenant sensor whose reported local policy `targets.allow` contains the target; platform sensors never; zones stay for routing | owner decision pending |
| R6 | Approvals, tiers, requests | Strict only (RFC-073) | unchanged | — |
| R7 | Exclusions, deny list, public suffixes, CIDR caps, audit, signer ledger, sensor local policy | always on | unchanged, always on; a bulk add runs every item through them | — |

### 14.2 Bulk add

`POST /scope/targets/bulk` (`attack_surface:scope:write`)

```json
{ "items": [{"target_type": "domain", "pattern": "api.example.com"},
            {"target_type": "ip_address", "pattern": "203.0.113.9"}],
  "reason": "", "origin": "refusal_fix" }
```

- 1 to 200 items (the dry run's limit, so a scan's refused targets fit in
  one request); `reason` is recorded on every entry; `origin` may be
  `refusal_fix`, otherwise the entries are recorded as `import`.
- A caller who adds entries directly (Off and On, or an approver in Strict)
  needs a recent re-authentication once: without it the request answers
  `403 STEP_UP_REQUIRED` and nothing is written. A Strict member's items
  follow the request rules of §6.1 per item (one-off, single, reason).
- Each item is `scope.Service.CreateTarget`: guardrails (§8), duplicates
  (the caller's tenant only), the Strict rules, the signer ledger before the
  write (an item the signer refuses is not saved and answers its code), the
  scope join, one audit event `scope_target.created` per entry. Waiting scans
  (§12.8) and a discovery sweep start once for the batch.
- One in-app notice to every owner and administrator for the entries that
  took effect ("N scope entries added", up to ten named); a pending item
  notifies as a single request does.

Response `200`:

```json
{ "results": [
    {"target_type": "domain", "pattern": "api.example.com", "result": "created", "id": "…", "status": "active"},
    {"target_type": "domain", "pattern": "old.example.com", "result": "exists", "id": "…", "status": "active"},
    {"target_type": "domain", "pattern": "*.com", "result": "refused", "code": "PUBLIC_SUFFIX", "message": "…"}],
  "created": 1, "existing": 1, "refused": 1 }
```

### 14.3 Threat model of the relaxations

| Relaxation | Abuse case | Control | Residual |
|---|---|---|---|
| R1 | a stolen session pastes 200 third-party names | step-up (a cookie alone fails), guardrails per item, one high-severity notice naming the batch, audit per entry, signer per entry, rate limits | a malicious organization adds many entries, as it could one by one; third parties are protected by the platform's proof setting for platform sensors and the deny list |
| R1 | cross-tenant oracle through `exists` | duplicates are looked up in the caller's tenant only | none |
| R3 | a lookalike confirmed by mistake | exact entry only, a person's action, audited, notified, Off and On only, exclusions and tombstones win | the confirmation now also authorizes scanning; the scan's intensity and approval rules still apply |
| R4 | dangling DNS or shared hosting points an in-scope name at a third party | suggestion only, shared addresses left out, exact addresses, a person accepts seeing the name each came from; the sensor pins resolution | a released cloud address still in DNS until the record is fixed |
| R5 | a compromised platform orders a tenant sensor to scan an internal range | the authority is the host operator's own local policy, which the sensor enforces on every signed job; platform sensors and sensors without a local policy are not eligible | an operator who allows a wide internal range chose it |

### 14.4 Plan

| Phase | Items |
|---|---|
| P0 | R1 bulk add (API); inventory "Add to scope"; pasting a list on the Scope page |
| P1 | R3, R4, R5 after the owner's decision; "Add host to scope" on findings |
| P2 | connector assets as scope: implemented with a per-connector switch **default on** (owner decision 2026-10-11, §14.5; supersedes the default off proposed here); the scan preflight explains a sensor's local-policy refusals from its reported policy |

### 14.5 Decisions 2026-10-13: the attack surface review flow

The owner adopted option B of the review-flow study: the attribution review
queue stops acting as a gate. Only two kinds of decision still need a person,
addresses behind in-scope names and names found outside every entry, and each
is offered as one grouped suggestion. Everything else follows from data the
organization already stated. Scope entries and exclusions stay the only
authority; nothing below adds authority without a person or the
organization's own connector.

| # | Decision | Implementation |
|---|---|---|
| D1 | An active scope entry, a one-off entry included, lets probes reach a name whose attribution automation left pending (`needs_review`, `candidate`); the record stays pending and the asset does not join the inventory. A person's decision (a pending state a person set, `dependency`, `monitor_only`, `rejected`), a rejected parent name, a tombstone and an exclusion still refuse, and an expired entry lifts nothing. A service or URL never gets more than its host. | `easm.ActiveGate` (`automaticPending`, `hostRefusals`); architecture `active-probe-gate.md` |
| D2 | Services, certificates and web endpoints follow their host: linked by a stored relationship of the tenant (`exposes`, `serves_certificate`) or the host in their own name, only when exactly one host exists; the host's state cascades to its automatic children; a person's decision on a child ends the link; the queue lists the host with its children counted. A one-time migration linked existing pending children of pending hosts without changing state. | `asset_attributions.follows_host_id`; `postgres.LinkChildren`; architecture `easm.md` §4 |
| D3 | R3: a person's confirmation adds the exact entry (`confirm_adds_to_scope`, default on; Strict and callers without the scope write permission record ownership only). Step-up once for the batch before anything is saved; one admin notice; an audit event per entry; origin `confirmed_asset`; the answer names each entry so Undo deletes exactly those. No backfill: earlier confirmations appear as a suggestion card. | `easm.ConfirmScope`; architecture `easm.md` §5a |
| D4 | R4: addresses behind in-scope names are one suggestion card; accepting it is an ordinary bulk add (§14.2) of exact address entries. Shared and CDN addresses are listed apart and never offered; an address whose network is unknown is marked so. Nothing is added automatically. | `GET /easm/suggestions` (`easm.SuggestionService`); architecture `easm.md` §4b2 |
| D5 | The Attack surface page shows these decisions as cards (a Decide panel); the Review tab is renamed Suggestions and its badge counts cards, not rows; the row list stays one click away. | web `easm-decide-panel.tsx` |
| D6 | Connector assets are in scope by default: after a successful sync, the public names and addresses a tenant connector synced get their exact entries as the system (origin `connector`, audited, one notice per sync), with a per-connector switch `assets_in_scope` (default on); each connector's first sync only notifies the administrators; Strict adds nothing. | `easm.ConnectorScope`; architecture `tenable-sc-connector.md` |

Threat model of D1–D6 (in addition to §14.3):

| Decision | Abuse case | Control | Residual |
|---|---|---|---|
| D1 | a scan reaches a discovered third-party name | only an entry the organization added (scope write, step-up, guardrails) lifts the record; a person's "not ours" or "monitor only" and exclusions win; a typed scan alone never lifts it | the organization scans what it put in scope, as for any entry |
| D2 | a child is confirmed through the wrong host | links only from the tenant's stored relationships or the child's own name, exactly one host, automatic records only, composite tenant foreign key | a wrong relationship written by a scan of the tenant's own sensor |
| D3 | a lookalike confirmed by mistake becomes scannable | exact entry, step-up, notice, audit, undo; off under Strict and per setting | as §14.3 R3 |
| D4 | dangling DNS points an in-scope name at a released address | suggestion only, shared addresses left out, unknown networks flagged, the person sees the names each address came from | as §14.3 R4 |
| D6 | a misconfigured or compromised connector widens scope | exact entries with guardrails per item, a notice before the first change and per sync, audit, per-connector switch, Strict adds nothing | entries for names the connector really reports |

## 15. Amendment 2026-10-13: inventory first, scope later

Owner decision: what discovery finds joins the assets at once; the
organization filters it and marks what is not in scope afterwards. Review
before inventory was too much work for no safety gain, because inventory
membership never authorized anything. Design study: research/124 (local).

### 15.1 Principle

- **Inventory membership means "we saw it"**: automatic, no review.
- **Active probes need scope**, unchanged: active entries, exclusions, the
  deny list, governance and the signer ledger (§4.2, §8). Inventory state
  never grants authority.
- A discovered asset that no entry covers is in the inventory and gets
  **passive checks only**. That is how the platform still never actively
  scans a third party.

### 15.2 The `discovered` state

| Item | Rule |
|---|---|
| Stored value | `asset_attributions.state = 'discovered'`; automatic only (a person's decisions are the other states) |
| Written | by every automatic writer (scan stamper, CT promotion, scope join) through `AttributionRepository.SaveAutomatic`: an automatic `needs_review` decision is stored as `discovered` unless the tenant keeps the review gate (§15.4); read in the same statement from the asset's own tenant |
| Raised | to `confirmed` by the scope join (§4.3, a permanent entry covers it) or a verified root; automation never lowers a confirmed record |
| Typed scan | a scan that names it adds evidence and does not confirm it (research/22 E7) |
| Inventory | in (`InInventory`, filter `approved`); filter `attributed` leaves it out |
| Gate | as an automatic pending record (§14.5 D1): an active entry covering it, a one-off entry included, lets probes reach it; otherwise refused with code `no_entry` ("not in scope: passive only") |
| Passive work | DNS checks only under an entry (as before for pending names); never a CT watch-list root; findings stay capped at P2 |
| `candidate` | unchanged: an unsolicited sensor report stays hidden (RFC-040 mutual distrust) |

### 15.3 Wildcard-only names

A name that resolves only through a wildcard DNS record of its zone may be
any name at all. Such a name is discovered like any other (it is in the
inventory), and the wildcard-DNS mark of RFC-088 decision A4
(`asset_wildcard_dns`) keeps it passive: the scope join never confirms it and
the gate refuses it with code `wildcard_only`, whatever entry covers it,
until a person confirms that asset or a later resolution clears the mark.
The inventory shows the mark as a filter and a badge.

Whether an entry covers an asset is never stored: it is computed when the
list or the gate asks.

### 15.4 Keeping the review gate

Scope setting `review_before_inventory` (default off; `PUT /scope/settings`,
scope approve permission and step-up, audited; omitted keeps the stored
value). When on, new automatic findings outside every permanent entry are
stored as `needs_review` and wait outside the inventory as before §15. Meant
for organizations that run scan approval Strict; it never changes what may
be scanned.

### 15.5 Migration

Migration `inventory_first_discovered`: the state constraint gains
`discovered`; every automatic `needs_review` record (no person decided it; children that follow
a host included) of a tenant without `review_before_inventory` becomes
`discovered`. A person's `needs_review`, `candidate` and every other state are
left alone. Idempotent; down restores `needs_review` (exactly the old
meaning).

### 15.6 Metrics

Dashboards, attack-surface counts and recent changes, the exposed-surface
counts and the CT watch list count the **attributed** inventory
(`AttributedSQL`, filter `attributed`): what the organization claimed or its
entries cover. Discovery noise never inflates the surface or risk. The scope
coverage count (§6.8) counts `discovered` as inventory, so what no entry
covers shows.

A request may ask for the whole inventory with `include_discovered=true`
(`shared.WithDiscoveredAssets`, `postgres.MetricsInventorySQL`) on
`/dashboard/*`, `/attack-surface/*` and `/easm/summary`, `/easm/changes`. It
changes counts only, never what may be scanned; the review queue and
rejected assets stay out. The Attack surface overview has the switch
"Include discovered assets" (off by default).

### 15.7 Threat model

| Threat | Control | Residual |
|---|---|---|
| a discovered third-party name is actively probed | inventory grants nothing; `discovered` is refused unless an entry the organization added covers it; exclusions, rejections and tombstones win; every dispatch path (scan create, quick scan, trigger by schedule or automation, workflow step, hop gate) goes through the one gate | the organization scans what it put in scope |
| a wildcard zone floods the inventory and its names are probed under a wildcard entry | the RFC-088 A4 mark refuses (`wildcard_only`) until a person confirms; never auto-confirmed | names a person confirms |
| a discovered domain widens passive lookups | CT roots are attributed assets only; DNS checks of discovered names need an entry | none new |
| cross-tenant | every write and read is pinned to the tenant; the migration joins each record to its own tenant | none |
| a hostile sensor fills the inventory | unsolicited reports stay `candidate`, hidden | as before |
| a Strict organization loses its review step | `review_before_inventory` | rows migrated before the setting was turned on stay in the inventory; they can be filtered and marked out of scope |

## 16. Amendment 2026-10-14: unclassified assets, low-impact checks, guardrails

Owner decision: an asset that no scope entry covers and that nobody excluded
or rejected (**unclassified**) is no longer passive only. It gets the
**low-impact** profile of active checks, unless a **platform guardrail** keeps
it passive. The organization filters afterwards (marks things out of scope,
rejects them, or adds them to scope for the full scan). Design study:
research/124 (local).

### 16.1 Intensity by asset state

The platform decides the intensity a target may get and caps each job to it;
the sensor only enforces.

| Asset state | Active checks |
|---|---|
| In scope (an active entry covers it) | the scan's tier, as before |
| Unclassified, passes the guardrails | passive in full, plus the low-impact profile (§16.3) |
| Unclassified, guardrailed (§16.2) | passive only (code `guardrailed`) |
| Excluded, rejected, "Not ours", deny list, wildcard-only, held by a person | nothing active, as before |

Unclassified means: an inventory asset with no record, an automatic pending
record (`discovered`, `needs_review`, `candidate` written by automation), or a
confirmed record that no entry covers. Typed text that names no inventory
asset is not unclassified: it still needs an entry (the platform is not a
free scanner of arbitrary names). When the asset is later added to scope it
gets its full tier on the next job: whether an entry covers it is computed at
dispatch and again at claim, never stored.

### 16.2 Platform guardrails

Always on; no tenant setting changes them (`easm/guardrail.go`):

| Guardrail | Reason code |
|---|---|
| address in a CDN, shared-hosting or cloud-provider network (its record's `cdn`, a provider holder, a published CDN edge range) | `shared_network` |
| address nothing is known about (no ASN or holder) | `network_unknown` |
| address that names of 3 or more registrable domains resolve to | `shared_hosting` |
| name whose registrable domain is none of the organization's (its non-program scope entries and verified domains) | `foreign_domain` |
| anything the classifier cannot place, and every asset when a lookup fails | `unplaceable`, `unavailable` |

Neither the organization's name nor a network seed lifts the shared-network
guardrail: both are the tenant's own assertions, and an organization renamed
after a CDN must not reach its edges. Bug-bounty program entries never make
a domain the organization's. Network data on an address (ASN, holder, CDN)
comes from enrichment and scans; a tenant that forges it reaches only the
low-impact profile, and the shared-network guardrail still holds edges.

A guardrailed asset stays in the inventory, gets passive enrichment, and the
asset page shows the reason. "Allow scanning" creates the asset's exact
scope entry through the scope service (scope write, step-up, approvals in
Strict, audit); that is the only way past a guardrail.

### 16.3 The low-impact profile

Defined once, `scopedom.LowImpact*` (`pkg/domain/scope/low_impact.go`):

| Item | Value |
|---|---|
| Tools | naabu, httpx, nuclei, dnsx, tlsx, subfinder, rdap, asn; anything else is refused |
| Ports | 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443 (TCP connect); never top-N or full ranges |
| HTTP | GET of `/` and `/.well-known/*` only |
| nuclei | severity `info` only, tags `tech` or `exposure` only; no template ids, workflows, custom templates or out-of-band callbacks |
| Rate | `rate_limit` (and naabu `rate`) at most 10 per second, set |
| Concurrency | `concurrency` and `bulk_size` at most 2 |
| Tier | T1; a T2 job is refused (`tier_exceeds`) |

Enforcement: the claim-time re-check (the one point that knows the tool and
its settings) refuses a job on an unclassified target that goes beyond the
profile (code `low_impact`), whatever the sensor: signed scope limits carry
ports, not template or rate caps. When every target of a job is refused only
for such a cap, the job is **clamped** instead (ports cut, rates and
concurrency lowered, nuclei narrowed to info/tech/exposure) and handed out; a
job that mixes in-scope and unclassified targets keeps its in-scope targets.
The tool settings are read from both `config` and `scanner_config`; a key set
differently in the two is unreadable and refused.

### 16.4 Port scans of names

A name never authorizes its addresses (S4). A port scan (naabu) of a name
reaches every port only when every address the name resolves to may be
port-scanned on its own: an entry covers it, or it is unclassified, passes
the guardrails and the mode is `full`. Otherwise it is limited to the web
ports 80, 443, 8080 and 8443 (code `web_ports_only`), or to the low-impact
ports when an address is only unclassified in `low_impact` mode. A name whose
addresses are unknown gets the web ports (fail closed). Other tools are not
narrowed by this rule.

### 16.5 Setting

Scope setting `unclassified_scans` (`PUT /scope/settings`, scope approve
permission and step-up, audited at high severity, administrators notified;
omitted keeps the stored value):

| Value | Meaning |
|---|---|
| `low_impact` (default) | §16.1 to §16.4 |
| `off` | the rule before §16: unclassified assets are passive until an entry covers them |
| `full` | unclassified assets that pass the guardrails get the scan's tier; still guardrailed |

The Strict scan approval mode forces `off` (`unclassified_scans_effective`).
An unreadable setting is `off`.

### 16.6 Job signer ledger

The signer's ledger (RFC-040 §5.6) is unchanged: it signs only targets inside
approved entries. An organization whose ledger enforces therefore keeps the
rule before §16 for unclassified assets (the signer refuses the job). That is
deliberate: the ledger is the organization's own approval record, which a
platform default must not widen.

### 16.7 Threat model

| Threat | Control |
|---|---|
| a third party's host gets probed because a name points at it | guardrails (shared network, unknown network, shared hosting, foreign domain); low-impact profile; name port scans limited to web ports while an address is held |
| a tenant uses unclassified scanning to scan arbitrary targets | typed text that names no asset still needs an entry; foreign-domain guardrail; unknown networks guardrailed; deny list; low-impact caps |
| forged network data on an address | reaches only the low-impact profile; CDN edges held by range regardless |
| a classifier lookup fails | the asset is guardrailed; a failed address lookup for a name's port scan fails the check (nothing dispatched) |
| a job escapes the cap through settings | the re-check reads both config maps; conflicting values are refused; the clamp's output is checked against the profile before hand-out |
| cross-tenant | every lookup (records, assets, relations, settings, entries) is pinned to the caller's tenant; another tenant's asset is never admitted |
| Strict organizations | forced off |

## 17. Amendment 2026-10-15: repository entries and CI trusts

Owner decision, 2026-10-15: when CI/CD adds a trust, the repositories it trusts join scope. Trusting
`gitlab.com/acme` adds `gitlab.com/acme/*`. With scan approval off there is no extra step, and proof is evidence,
not a gate. The owner also decided that self-hosted code hosts may be claimed whole.

### 17.1 Repository entries

- **Form.** A repository entry is `host/namespace/repo`, `host/namespace/*` (every repository below the namespace,
  at any depth, so GitLab subgroups are included) or `host/*` (every repository on a self-hosted host). It is
  stored in canonical form: lower case, without a scheme, credentials or `.git`. `/**` is written as `/*`.
- **Matching** is per path segment: `gitlab.com/acme/*` covers `gitlab.com/acme` and `gitlab.com/acme/sub/app`,
  never `gitlab.com/acme-evil/app`. Repository exclusions use the same matcher.
- **Shared code hosts** (github.com, gitlab.com, bitbucket.org, dev.azure.com, codeberg.org and the others in
  `pkg/domain/scope/public_code_hosts.txt`, plus the operator's `SCOPE_PUBLIC_CODE_HOSTS_EXTRA`):
  - a whole-host entry is refused with `SHARED_CODE_HOST`;
  - repositories there are judged by repository entries only, so a domain entry for the host (`github.com`)
    claims nobody's repositories.
  - On any other host, an entry for the host covers its repositories, and `host/*` is allowed.
  - The deny list applies to code hosts.
- **Verdict.** A repository asset gets a scope verdict, `in_scope` with the covering entry or `out_of_scope`,
  instead of `not_applicable`.

### 17.2 A CI trust's managed entries

- **Which trusts.** With `manage_scope` ("Trust and add to scope"), a GitHub trust (github.com or GitHub Enterprise
  Server) or a GitLab trust (gitlab.com or self-managed) claims `<host>/<owner>/*` per owner rule. Per repository
  rule it claims `<host>/<repo>`, or `<host>/<prefix>/*` for a rule with a wildcard. Other providers name the code
  host per run and claim nothing.
- **Who and how.**
  - Only a caller holding `attack_surface:scope:write` turns it on (`403 MANAGE_SCOPE_FORBIDDEN` otherwise). For
    anyone else it defaults to off.
  - Such a caller may rename or narrow a scope-managing trust, never widen it.
  - The entries are created as that person, through the same decision as a hand-added entry (step-up, approval
    right, approval mode). With scan approval off they are in effect at once. Under Strict, an approver's entries
    wait for their approvals, and anyone else's are not added; the refusal is audited.
- **Linking and lifecycle.**
  - An equal existing entry is linked, never duplicated, and stays its owner's.
  - Entries the trust created (origin `ci_trust`) follow it: an edit moves them, disabling or deleting the trust
    retires them, and overlapping trusts share one entry until the last goes.
  - A managed entry refuses tier, expiry, reason, discovery, activate, deactivate and delete through scope
    (`409 CI_TRUST_MANAGED`). To keep one repository out, add an exclusion.
  - An existing entry a person deletes is recorded on the link and is never created again by the trust.
- **Evidence.** The first verified, tenant-bound pipeline run under a pattern is recorded (time, run, repository,
  owner id) and shown on the trust and the entry. A legacy-audience run never counts. A run never creates an entry;
  it may only link an existing equal one.
- **Opt-in governance.** The scope setting `ci_scope_requires_proof` (default off) keeps new managed entries
  inactive until such a run.
- **Existing trusts** keep `manage_scope` off. An administrator turns it on per trust. `ci-trust-scope-plan` is the
  read-only dry run of what that would do.
- **What a repository entry authorizes.** Nothing about network probes changes. Platform code scanning
  (RFC-091) clones only with a credential from the organization's own code-host connection; a trust or an entry
  never yields one.

### 17.3 Data

Migrations `002193_ci_trust_managed_scope` (renumbered at merge as needed) add:
- `ci_trust_configs.manage_scope`;
- the origin `ci_trust`;
- the table `scope_target_ci_trusts` (tenant, trust, pattern, target, evidence, `target_removed_at`), with
  composite `(tenant_id, …)` foreign keys.

### 17.4 Threats

| Threat | Control |
|---|---|
| A whole shared host claimed (`github.com/*`), or claimed through a domain entry | `SHARED_CODE_HOST`; repository-only judging on shared hosts |
| A look-alike namespace | Per-segment matching |
| Scope widened through CI permissions alone | `manage_scope` needs scope write; entries are created as the caller under the normal decision |
| Approval governance bypassed | Same decision path as a hand-added entry |
| An entry a person deleted comes back | Recorded on the link; runs and trust changes never create it again |
| Another organization's public namespace trusted | The entry is labelled with no verified run; opt-in proof keeps it inactive; no clone credential, no network authority |
| Cross-tenant links or evidence | Tenant-filtered queries, composite foreign keys, evidence only from the tenant's own verified exchange |
