# RFC-073: Scan approval governance (approve scans, not scope entries)

| | |
|---|---|
| Status | Accepted (owner decision 2026-10-10); P0 in progress |
| Scope | api (`pkg/domain/scangov`, `internal/app/scangov`, `internal/app/scanpolicy`, `internal/app/scope`, `internal/app/scan`, signer ledger), web (Settings > Scanning, New Scan, Approvals, admin console) |
| Architecture | [scan-approval.md](../architecture/scan-approval.md) |
| Related | RFC-054 (scope model; §7 and §12 approvals amended here), RFC-040 §11.5 (signer ledger; amended in §7 here), RFC-071 (scan intensity), RFC-067 (scan windows) |

## 1. Summary

Approvals and tier limits are opt-in and follow the organization's risk
appetite. When an organization turns them on, people approve **scans**
(what runs, how hard, against what, when and where), not scope entries.

1. **Off by default.** Adding a scope entry needs no approval and an entry
   has no tier ceiling: in Off and On a scope entry is a list of targets
   (with exclusions), and how hard a target may be probed is the scan's
   business (intensity, approval rules); members with scan permission
   create and run scans directly. Entry tier ceilings (`max_tier`) apply
   only in Strict. Audit, step-up on widening scope, exclusions, the deny
   list and domain proof for platform sensors are unchanged.
2. **A tenant setting "Scan approval": Off, On, Strict.** Owner only, with
   step-up re-authentication and a reason; audited high.
3. **A platform administrator can force it** per organization or as the
   platform default: `tenant_controlled` (default), `off`, `on` (at least
   on), `strict`. This reuses the RFC-054 §12.6 platform policy, renamed to
   scans.
4. **Approval rules** decide which scans need approval (On, Strict), by
   intensity, tools, target tags, criticality, crown jewels, dynamic
   selectors, blast radius, schedule, sensor placement and zone. Strict
   means two distinct approvers and a justification on every caught scan,
   and keeps the scope-entry approvals of RFC-054.
5. **What is approved is the scan definition** (its digest): runs of an
   approved definition need nothing more; any change to the approved fields
   needs a new approval, with the diff shown to approvers.

## 2. Threat model

| Actor | Goal | Control |
|---|---|---|
| Careless member | runs an intrusive scan on production by mistake | rules (intrusive, production tag, criticality, crown jewel) hold the run until an approver agrees; the approver sees targets, intensity, tools, schedule and the rule that caught it |
| Compromised member session | runs a wide or intrusive scan | the same rules; the requester never approves their own request; approvals are bound to the definition digest, so a later edit needs a new approval |
| Compromised admin session | turns governance off or loosens the rules | the mode is owner-only, the rules owner or administrator, both need step-up re-authentication (a stolen cookie alone is not enough) and a reason; audited high |
| An operator relaxes an organization silently | forced Off | super_admin, a fresh console authenticator code, a reason, critical admin audit, the other platform administrators emailed and the organization's administrators told |
| Malicious organization (colluding people) | uses the platform to scan a third party | approvals do not help (they approve each other) and never did: ownership proof for platform sensors, the platform deny list, public-suffix refusal and CIDR caps stay always on (RFC-054 §8) |
| Cross-tenant | reads or changes another organization's rules or requests | every read and write is the authenticated tenant's own settings section or rows (`tenant_id` from the principal); the platform override has no tenant route |

Turning governance off is the guarded direction. A read error of the mode
fails closed: scope entries count as Strict (they keep approvals) and a run
is refused.

## 3. Decisions

| # | Decision |
|---|---|
| G1 | Off is the default for every organization, including existing ones (owner 2026-10-10). |
| G2 | The tenant mode is a settings section (`tenants.settings.scan_governance`): `mode`, `rules`, `pending_expiry_days`. Mode: owner, step-up, reason. Rules: owner or administrator, step-up, reason. |
| G3 | The platform policy is `tenants.scan_approval_policy` + `platform_settings.scan_approval_policy`: `tenant_controlled` (default), `off`, `on`, `strict`. Migration `001881` renames the RFC-054 column and maps `disabled` to `off`, `required` and `tenant_controlled` to the default. Minimal back-compat: the old values had no meaning once entries stop needing approval outside Strict. |
| G4 | Turning On with no rule seeds the Light preset (intrusive scans need one approval), so On is never silently empty. |
| G5 | Rules: conditions AND inside a rule; rules OR'ed; every matched rule is shown; the matched rule asking the most approvals (first on a tie) decides who approves; justification and ticket requirements and ticket formats add up; the shortest validity wins. Monitor-mode rules record "would need approval" without blocking. |
| G6 | Strict: at least two distinct approvers and a justification for every caught scan; scope entries keep RFC-054 §7 approvals and their tier ceilings. Off and On: no entry tier ceiling (owner 2026-10-10): an entry's `max_tier` is kept (it applies again when the organization turns Strict on) but nothing refuses a probe for it. The T2 duration and attestation rules of RFC-054 §12.4/12.5 still bound entries marked t2 in every mode, so turning Strict on never revives a stale intrusive grant. |
| G7 | The approval covers the scan definition digest: targets and selectors as written (a `*.domain` or CIDR is approved as a pattern; each run resolves it again within it), asset groups, target options, scan type, scanner and configuration, workflow and the tools of its steps, profile, intensity, schedule, sensor placement, zone and routing tags. Name, description, retries and timeouts are not in it. |
| G8 | Signer ledger: see §7. Standard modes keep the ledger's guarantee against database writers and every path that bypasses the scope service; they drop the recorded-approval requirement and the tier ceilings for entries, in the ledger exactly as in the database. Strict keeps both. |

## 4. Settings

`GET /api/v1/organization/settings/scan-governance` (`scans:read`):
`mode` in force, `source` (`organization` or `platform`),
`organization_mode` (the owner's choice), `platform_policy`,
`selectable_modes`, `scope_entries_need_approval`, `rules`,
`pending_expiry_days`, `presets` (`light`, `standard`, `strict`).

`PUT .../scan-governance/mode` `{"mode": "on", "reason": "..."}`: owner,
step-up; `403 SCAN_APPROVAL_FORCED` when the platform policy overrides the
choice. `PUT .../scan-governance/rules` `{"rules": [...],
"pending_expiry_days": 14, "reason": "..."}`: owner or administrator,
step-up; at most 50 rules. Both are compare-and-swap section writes
(`If-Match`), audited `scan_governance.mode_changed` /
`scan_governance.rules_updated` at high severity with the reason.

### 4.1 Rule

```json
{
  "id": "uuid", "name": "Active scans on production", "enabled": true, "monitor": false,
  "conditions": {
    "min_intensity": "active", "tools": ["hydra"], "asset_tags": ["production"],
    "min_criticality": "high", "crown_jewel": true, "dynamic_selectors": true,
    "targets_over": 500, "cidr_wider_than": 24, "recurring": true,
    "sensor_placement": "platform", "zone_ids": ["uuid"],
    "requester_roles": ["member", "uuid"], "requester_group_ids": ["uuid"],
    "origins": ["api_key", "service_account", "mcp", "ci"],
    "trusted_service_account_ids": ["uuid"],
    "hours": {"match": "outside", "timezone": "Asia/Ho_Chi_Minh",
              "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "09:00", "end": "18:00"}]}
  },
  "requirement": {
    "approvals": 1, "approver_roles": ["admin"], "approver_user_ids": ["uuid"],
    "require_justification": true, "require_ticket": true, "ticket_pattern": "CHG-[0-9]+",
    "validity": "definition", "validity_days": 0
  }
}
```

Ticket patterns are RE2 (linear time), anchored, at most 200 characters.

Requester and time conditions read who asks for the scan (or starts the
run), through what, and when it runs:

- `requester_roles`: the requester's effective role (`owner`, `admin`,
  `member`, `viewer`) or the id of any role they hold in the organization;
  `requester_group_ids`: any active group of the organization they belong to.
- `origins`: how the action authenticated, recorded by the authentication
  middleware (never from the request body): `ui` (a person's session),
  `api_key` (a person's `oct_` key), `service_account` (an `oct_` key of one
  of the organization's service accounts), `mcp` (the MCP endpoint), `ci`
  (a CI run token), `system` (no caller: the scheduler, an automation).
- `trusted_service_account_ids`: service accounts this rule never catches.
  Only an id the directory confirms is a service account of this
  organization is exempt; a person's id in the list exempts nobody.
- `hours`: a weekly schedule (1 to 14 windows of weekdays and `HH:MM`
  start/end, end up to `24:00`), `match` `outside` (default) or `inside`,
  in `timezone` (IANA) or else the organization's timezone (Settings >
  General), else UTC. Wall-clock times, so the windows follow daylight
  saving.

Who and when. A run: the person who starts it through the origin of the
request; a scheduled run is `system` acting for the scan's creator; the
time is now. A request, the approval state and the New Scan preview: the
person asking, at the scan's next scheduled run when one is set in the
future, else now. Every run is evaluated again at the gate, so an
approval obtained in office hours still covers an approved definition
whose validity covers the later run; use `validity: run` for per-run
approvals. Fail closed: an unknown requester or origin is caught by every
requester condition, an unknown time or timezone by every hours condition,
and a failed directory lookup refuses the run. Today `oct_` keys and the
MCP endpoint are read-only and CI run tokens only upload results, so
`api_key`, `service_account`, `mcp` and `ci` rules take effect when those
callers may start scans.

Conditions our data does not support yet are documented as later (§9):
blackout overrides; business unit, asset group and environment beyond
tags; bug-bounty program targets; targets outside verified domains;
change-ticket lookup in the Jira integration; approver-added constraints
(run window, rate cap). Asset owners as approvers: §10.

### 4.2 Presets

Off (default) · Light (intrusive scans, one approval, justification) ·
Standard (Light + active scans on production-tagged, high-criticality or
crown-jewel assets, and active scans of more than 500 targets) · Strict
(Standard with two approvers and a change ticket).

Use cases these cover (tests and docs): a bank change-advisory board
(active on production needs a ticket and the CAB approvers; intrusive needs
two); OT zone scans (zone condition, named plant engineers); wide blast
radius (> 500 targets or wildcard/CIDR selectors, security lead);
credentialed or brute-force tools (tool condition, security lead).

### 4.3 Rule tester

`POST /api/v1/organization/settings/scan-governance/test` `{"rules": [...]}`
(owner or administrator; no step-up, it writes nothing): the rule set is
validated as a save would validate it, then evaluated against the
organization's saved scans (at most 200, newest first), each as a run its
creator starts from the console at its next scheduled time (else now). Off
is evaluated as On (what turning it on would do), Strict as Strict. The
answer lists the scans it would hold for approval (with the matched rules
and the merged requirement), those only monitor rules catch, how many
scans each rule catches, and whether the organization has more scans than
were tested. Only the caller's organization's scans are read.

## 5. Platform policy

`GET/PUT /api/v1/admin/settings/scan-approval-policy` (platform default)
and `GET/PUT /api/v1/admin/tenants/{tenantId}/scan-approval-policy`
(override; `policy: null` follows the default). Reads: any platform
administrator; the organization response adds `effective_mode`. Changes:
super_admin, a fresh console TOTP code, a reason; critical admin audit
(`platform.scan_approval_policy_changed`,
`organization.scan_approval_policy_changed`); the other platform
administrators emailed; the organization's administrators told in-app.
Forced `off` and `strict` refuse every owner change; forced `on` lets the
owner choose On or Strict.

## 6. Scope entries

`scope.Service` reads the organization's mode in force
(`scanpolicy.Service.ScanGovernanceMode`): in Off and On a widening needs no
approval (`approvals_required = 0`, the entry is in effect at once) and the
entry is not a tier ceiling; in Strict RFC-054 §7 applies unchanged (the tenant's 0/1/2, at least one with
two or more administrators and for t2, the sole-owner self-approval). In
every mode: step-up on every widening route, the dry run, a member without
`attack_surface:scope:approve` only requests (the request still waits for
an approver), exclusions, ownership proof, deny list, CIDR caps, audit and
notification. `GET /scope/settings` returns `approval_policy:
{scan_approval, source, entries_need_approval}`; the owner-only
`tenant_controlled` approval count of RFC-054 §12.6 is removed.

Tier ceilings. The dispatch gate's tier check
(`easm.ActiveGate.TierExceeded`, which scan create, quick scan, scan
commands, runs, workflow steps and the dispatch gate all use) answers
nothing exceeded outside Strict (`scanpolicy.Service.TierCeilingsEnforced`;
an unreadable mode is Strict, fail closed). Coverage is unchanged: a target
outside every entry is still refused, exclusions still apply, intrusive
(t2) workflow steps still need ownership proof per step (RFC-054 §8.1),
and the scan's intensity and approval rules decide how hard it probes.
The entry form shows the tier only in Strict.

Migrating existing entries: nothing is rewritten. Entries already in effect
stay; an entry pending approval stays pending and is approved as before (an
approver approves it, or its requester withdraws it); new widenings in Off
and On take effect at once.

## 7. Signer ledger (amends RFC-040 §11.5)

RFC-040's ledger guarantees that a compromised API cannot widen what
sensors scan beyond what people authorised. Until P3 (WebAuthn assertions
the signer verifies) the approvals it checks are the approvals the API
recorded, so an attacker inside the API process can already claim them;
what the ledger reliably stops is a database writer and every path that
bypasses the scope service hook.

Decision. Scope-entry changes keep going through the one hook
(`commitEntry`/`commitExclusion`) in every mode, labelled with the mode
(`platform_policy: "scan_approval:off|on|strict"`). In Off and On an entry
widens with `policy_required_approvals = 0`; the signer's former hard
minimum of one approval for a t2 entry becomes an operator floor,
`SIGNER_LEDGER_T2_MIN_APPROVALS` (0 to 2, default 0, accepted by the owner
2026-10-10), next to `SIGNER_LEDGER_MIN_APPROVALS`.

Tier ceilings in the ledger. The ledger holds one more fact per
organization, its tier ceilings (on or off), so it is never wider than the
database and never refuses what the database allows:

- Operation `set_tier_ceilings` (`tier_ceilings: true|false`). Off widens
  (every entry then covers every tier, still only inside the entries and
  outside the exclusions); on narrows. The zero state is on, so a ledger,
  log or snapshot that predates it is the stricter one.
- Turning them off needs what an intrusive entry needs: the policy count
  (0 in Off and On) and the operator floors, `SIGNER_LEDGER_T2_MIN_APPROVALS`
  included. An operator who sets that floor above 0 therefore keeps every
  organization's ceilings (Off and On widenings that carry "off" are refused
  with `SCOPE_LEDGER_REFUSED`), which is the same as forcing Strict.
- Who sends it. A mode change that crosses Strict (the owner's choice,
  a platform override, or a platform default for the organizations that
  follow it) goes through `scope.Service.CommitTierCeilings`: leaving
  Strict is accepted by the signer before the mode is saved, or the change
  fails and the mode stays Strict (`SCOPE_LEDGER_REFUSED` /
  `SCOPE_LEDGER_UNAVAILABLE`); entering Strict is saved first and sent best
  effort. A platform default change tells every following organization
  that crosses Strict; one refusal fails the whole change and narrows back
  those already accepted. Every scope widening also carries the
  organization's ceilings as the database has them, so a new
  organization's ledger follows its mode from its first entry, and one
  whose mode change did not reach the signer catches up on its next
  widening.
- Sync (`POST /v1/ledger/sync`, snapshot `tier_ceilings_off`) turns the
  ceilings back on when the database is Strict, never off: a snapshot that
  says off while the ledger says on is counted as diverged. The ledger never
  takes a wider state from the database alone. Export and import carry the
  state.
- Rollout. Existing ledgers start with the ceilings on. Until an
  organization's next scope widening or mode change, the signer refuses a
  job above an entry's tier that the API (Off or On) allows: the stricter
  side, and visible as `tier_exceeds_ledger`. An operator who wants every
  organization in step at once exports the database's view
  (`server -signer-ledger-export`, which now carries `tier_ceilings_off`)
  and imports it into the stopped signer (`openctem-signer ledger import -replace`), the
  ceremony that already exists for trusting the database's view.

Trade-off. In Off and On the ledger still refuses jobs outside the
entries, still records every widening in its hash-chained log (detection
A10, SIEM export) and still stops database writers and bypass paths; it no
longer requires a recorded human approval for an entry, nor holds an entry
to its tier. As for approval counts, the mode the API states with a
widening is the API's (P2): an attacker inside the API process can claim
Off, and the operator floors are the defence against that. Scan approval does
not move into the signer in this RFC: approvals of scan definitions are
recorded by the API and checked at every run. **Strict keeps the RFC-040
guarantee as it was** (entries need their approvals, recorded and checked
by the signer). An operator who wants the guarantee for every organization
sets `SIGNER_LEDGER_MIN_APPROVALS` / `SIGNER_LEDGER_T2_MIN_APPROVALS` and
forces Strict through the platform policy; a widening without the
approvals is then refused (`SCOPE_LEDGER_REFUSED`), never silently
accepted.

## 8. Scan approval requests

A request records the definition (canonical JSON and digest), the matched
rules and merged requirement, justification and ticket, `run_on_approval`,
the requester, the approvals (`self` and `emergency` marked), validity and
expiry. One pending request per scan. Every run (manual, scheduled, quick,
started after approval) passes one gate: Off, or no rule requires approval,
or an approved request for the current digest that is still valid and has
at least the approvals the rules ask now (switching to Strict needs a
second approver for scans approved once); a run-only approval is consumed
atomically. Otherwise `SCAN_APPROVAL_PENDING` or `SCAN_APPROVAL_REQUIRED`
(a scheduled run is recorded as blocked). Approvers are the members with
`scans:approve` (owners and administrators by default) the decisive rule
allows; the requester never approves; an owner with no other approver
self-approves with a fresh authenticator code and a reason; Remind at most
hourly; pending requests expire. An emergency run: owner or administrator,
step-up, reason, 1-24 hours, audited critical, administrators told.

Routes (migration `001921`: `scans:approve` for owners and administrators,
`scan_approval_requests`):

| Route | Gate |
|---|---|
| `POST /api/v1/scans/approval-preview` | `scans:write`; evaluates an unsaved scan (New Scan review) |
| `GET /api/v1/scans/{id}/approval` | `scans:read`; required, approved, the current request, changes since the last approval |
| `POST /api/v1/scans/{id}/approval` | `scans:write`; submit (`justification`, `ticket`, `run_on_approval`) |
| `POST /api/v1/scans/{id}/emergency-run` | `scans:approve` + `scans:execute`, owner or administrator, step-up |
| `GET /api/v1/scan-approvals[/{id}]` | `scans:read`; the inbox (`status`, `scan_id`, paging), `can_approve` and the eligible approvers per request |
| `POST /api/v1/scan-approvals/{id}/approve`, `/reject`, `/self-approve` | `scans:approve`; the rule's approvers, never the requester |
| `POST /api/v1/scan-approvals/{id}/remind`, `/cancel` | `scans:write`; reminders hourly at most; only the requester withdraws |

The scan list carries `approval_status` (the newest request's status).
The definition's intensity is the scan's declared intensity (RFC-071),
never below the highest tier its tool or workflow steps probe at. Changing
the declared intensity changes the digest: it needs a new approval.

## 9. Plan

| PR | Content |
|---|---|
| Setting | modes, platform policy renamed to scans, rules and presets (validation, evaluation), settings API, scope entries Strict-only, signer t2 floor, admin console and scope page texts (migration `001881`) |
| Requests | `scans:approve`, `scan_approval_requests`, definition digest and diff, the run gate, submit/approve/reject/self-approve/remind/emergency, inbox API, list badge (migration `001921`) |
| Web | Settings > Scanning > Scan approval (mode; presets; rules on, off, monitor, remove), New Scan review "needs approval by…" with the evidence the rules ask and Submit for approval, Scans > Approvals inbox (details, diff, approve, reject, own approval with an authenticator code, remind, withdraw), scan list badge |
| Web, rule editor | the rule editor (condition chips, requirement form, drag order), the rule tester, approval state and emergency run on the scan page |
| Requester conditions | requester role and group, origin with trusted service accounts, business hours (§4.1) |
| Rule tester | `POST .../scan-governance/test` (§4.3) |
| Asset-owner model | `approver_source`, `fallback_group_id`, `SplitByOwner`, `PartsApproved` (§10); refused on save until enforced |
| Asset-owner approvals | parts on requests, inbox per part, gate (§10.4) |
| Later | monitor-mode report, the §4.1 later conditions |

## 10. Asset owners as approvers

The people who own an asset know whether a scan of it is safe this week.
A rule may let them approve instead of (or before) a central approver.

### 10.1 Rule

```json
"requirement": {"approvals": 1, "approver_source": "asset_owners",
                "fallback_group_id": "uuid"}
```

`approver_source`: `rule` (default: `approver_roles` and
`approver_user_ids`) or `asset_owners`. `fallback_group_id`: a group of the
organization that approves the targets nobody owns; without it the rule's
roles and people do (owners and administrators when the rule names none).

### 10.2 Parts

At submit the request's targets are split by owner (`SplitByOwner`): each
target maps to the asset behind it (direct targets by name, asset-group
members by id) and that asset's owners in `asset_owners` (a user owner, a
group owner). Every owner of a target gets it in their part, so a target
owned by a person and a group needs both. Targets with no owner, no known
asset, private addresses and wildcard or CIDR selectors go to the fallback
part (a selector is resolved at each run, so it cannot be owned in
advance). The parts are recorded on the request with the definition; a
change of ownership after submit does not change who approves an existing
request (the next definition change does).

### 10.3 Approving

- A part is approved by one of its approvers: the owner user; any active
  member of the owner group; the fallback group's members, else the rule's
  approvers. `PartsApproved` decides; the requester and a self-approval
  never count, and one approval counts for every part its approver may
  approve.
- The request is approved when every part is approved and the merged
  requirement holds (`approvals` distinct approvers overall; Strict: two).
  An owner approving a part needs no `scans:approve`: the rule delegates to
  owners. Owning an asset still grants no data scope: an owner sees the
  request's targets of their part, the scan name and requirement, not the
  other parts' targets.
- Reject: any part's approver rejects the whole request (with a note).
  Remind goes to the approvers of the waiting parts only.
- Emergency runs and the sole-owner self-approval are unchanged.

### 10.4 Enforcement order

The model (`approver_source`, `fallback_group_id`, `Part`, `SplitByOwner`,
`PartsApproved`) is in `pkg/domain/scangov/owners.go`. Until the request,
inbox and gate paths apply it, saving a rule with `asset_owners` is
refused (`400`), so no rule claims a control that is not applied. The
enforcement PR adds `parts` to `scan_approval_requests` (JSONB, recorded at
submit), the owner lookup (tenant-scoped `asset_owners` and
`group_members`), per-part decisions in approve and reject, the inbox's
per-part view and the gate's `PartsApproved` check, with tests for: an
owner approving only their part, a group member approving for the group,
the fallback group, the requester owning a part (someone else must
approve it), and another organization's owners never counting.

### 10.5 Threat model

| Actor | Goal | Control |
|---|---|---|
| Owner of one asset | approves a scan of assets they do not own | approvals count per part; their approval covers only parts they may approve |
| Requester who owns a part | approves their own part | the requester never counts, for any part |
| Member added to an owner group to approve | gains approval | group membership changes are audited (`team:groups:write`); the request records parts at submit |
| Cross-tenant | owner of a same-named asset elsewhere | owners are looked up by asset id within the tenant; group membership within the tenant |
