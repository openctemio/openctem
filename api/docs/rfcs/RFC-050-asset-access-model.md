# RFC-050: Asset access model

| | |
|---|---|
| Status | Accepted (owner approved A1–A13 as recommended, 2026-10-04); P0 in progress |
| Research | research/21 (target model), 21a (industry), 21b (current state on `develop`) |
| Supersedes | parts of research/15 §5 (target model); D1–D14 stay in force |
| Related | RFC-045 (socket revocation), RFC-040 (sensor binding), RFC-046 (scans), RFC-048 (filter compile) |

## 1. Summary

Every request is answered by one decision: *may principal P perform verb V on
resource R now?*

```
allow = same tenant
      ∧ principal active                (active membership AND active account)
      ∧ RBAC permission for V
      ∧ (full-data level ≥ level(V) ∨ every asset behind R is in P's scope at level(V), now)
      ∧ no forbid applies
```

Any error denies. A deny on a by-id route answers 404. Lists, counts, exports,
sockets and prompts use the SQL form of the same rule
(`user_accessible_assets`, which only ever holds rows for an active principal).

Layers: tenant boundary, RBAC, data scope (view/act), sensitivity
(`*:reveal`), time (expiry, engagement windows, elevations). Forbids
(exclusions, separation of duties, quarantine) override every permit.

Scope sources: S1 access group (manual + rules), S2 direct grant, S3
engagement, S4 break-glass elevation, S5 full-data role. Being an asset owner
is accountability, never scope (O1). No empty scope, empty key narrowing or
empty channel filter ever means "the whole tenant".

Non-human principals (keys, MCP, schedules, workflows, reports, AI, sensors)
act on behalf of a named principal re-checked at execution time; a missing or
inactive owner refuses, never falls back to the unrestricted system caller.

Architecture: keep the materialisation in Postgres, refreshed in the same
transaction as every source write; composite `(tenant_id, asset_id)` foreign
keys; RLS stays a tenant-only backstop.

The full catalogue of use cases, the threat model (STRIDE per principal,
failure classes F-1..F-12) and the gap list are in research/21; this RFC
records the decisions and tracks the implementation.

## 2. Member lifecycle (P0, first item)

A person is never hard-deleted. All access hangs off the tenant membership,
so one switch revokes it. Three actions, none deletes a row another table
points at:

| Action | Trigger | Effect | Reversible |
|---|---|---|---|
| **Disable** | Members page; SCIM `active=false` | membership `suspended`; in **one transaction**: user-bound API/MCP keys `suspended`, materialised scope dropped, owned scan schedules `paused`, owned report schedules and workflows deactivated. Groups, grants and ownership stay **frozen**. Sessions and refresh tokens revoked, permission version deleted (closes sockets, RFC-045), pending invitations removed. Administrators notified in-app when schedules were paused | yes: **Re-enable** re-activates the suspended keys and recomputes the scope from the frozen sources; paused schedules stay paused for an administrator to resume |
| **Offboard** | Members page (wizard); `DELETE /members/{id}`; SCIM delete | in **one transaction**: mandatory reassignment of owned scans, report schedules and workflows (`schedules_to`), open assigned findings (`findings_to` or `unassign_findings`) and owned assets (`assets_to`) to another **active member of the same tenant**; keys `revoked`; group memberships, grants, engagement memberships (and campaign lead/team entries), roles and pending invitations removed; membership kept as an `offboarded` **tombstone** (history and foreign keys stay valid). Nothing to reassign is required when nothing is owned. A plan that leaves owned work uncovered answers 409 `reassignment_required` with the missing categories | no: a re-invite (invitation, admin add, SCIM, SSO JIT) re-activates the tombstone **from zero** (only the new role) |
| **Erase personal data** | Members page, owner only | allowed only after offboarding and when the person belongs to no other organization (and is no platform administrator): name → `Deleted user #<hash>`, email → `erased-<hash>@erased.invalid`, avatar, phone, preferences, password, federated identity, second factor cleared, sessions revoked, `users.erased_at` set, status `inactive`. Rows and foreign keys stay | no |

SCIM delete cannot pick new owners: when the member owns work, the member is
disabled (access cut at once) and administrators are asked to finish the
offboarding. A re-provisioned person follows the newcomer rule (a verified
email domain, otherwise an invitation).

### 2.1 Fail-closed gates

- Every membership gate is a **positive** check (`membership.IsActive()`),
  never `!IsSuspended()`: the URL-tenant chain, the token-tenant chain
  (`/me`, notifications, WebSocket upgrade), permission sync, the API-key
  holder check, the peer-administrator rule, setup links.
- `users.status` must be `active` on every authenticated request (UserSync),
  not only at login.
- The data scope: `principal_is_active(tenant, user)` gates every refresh
  function (`refresh_access_for_user`, asset assign, member add, grant add,
  full refresh), `HasFullDataRole` (no full-data bypass for an inactive
  member) and `datascope.MembershipAdminLookup` (a background job acting for
  a disabled or offboarded administrator gets `ErrInactivePrincipal` and
  refuses).
- Tombstones are invisible: no token, no tenant switcher entry, not in the
  default member list (pickers), not in SCIM.

### 2.2 Threat model

| Threat | Control |
|---|---|
| A leaver or compromised account keeps acting through a live session, socket, key or schedule | Disable/offboard revokes sessions and refresh tokens, closes sockets, suspends or revokes keys, pauses schedules, drops scope in the same transaction; every gate is positive |
| Re-invite restores old access (L-13) | Offboarding strips groups, grants, engagements, roles, keys; the re-join starts from zero |
| Work silently runs as the system after the owner leaves (H2/H3 class) | Mandatory reassignment; disable pauses schedules; an inactive owner makes `ForUser` refuse |
| An administrator reassigns work to an outsider | Targets must be active members of the same tenant (checked in the transaction); cross-tenant and unknown ids answer 400 |
| An administrator removes a peer administrator | Peer-administrator rule: only the owner acts on an administrator |
| Erase destroys evidence | Erase is owner-only, after offboarding, keeps rows and foreign keys, audited Critical |
| Cross-tenant enumeration of memberships | Targets are loaded within the caller's tenant; anything else is 404 |

Every action is audited: `member.suspended` and `member.offboarded` High,
`member.reactivated` High, `member.data_erased` Critical; a refused
offboarding is audited with the missing categories.

### 2.3 API

| Route | Gate |
|---|---|
| `POST /api/v1/tenants/{t}/members/{id}/suspend` (Disable) | team admin + `members:write`, peer-admin rule |
| `POST /api/v1/tenants/{t}/members/{id}/reactivate` (Re-enable) | same |
| `GET /api/v1/tenants/{t}/members/{id}/access-report` | team admin + `members:read` |
| `POST /api/v1/tenants/{t}/members/{id}/offboard` `{schedules_to, findings_to \| unassign_findings, assets_to}` | team admin + `members:write`, peer-admin rule |
| `DELETE /api/v1/tenants/{t}/members/{id}` (offboard with no plan) | same |
| `POST /api/v1/tenants/{t}/members/{id}/erase` | team owner (and the service re-checks the owner) |
| `GET /api/v1/tenants/{t}/members?status=active\|suspended\|offboarded\|all` | `members:read`; default leaves tombstones out |

Migration `001033_member_lifecycle`.

## 3. Plan

### P0: close the remaining leaks

| # | Item | Status |
|---|---|---|
| W6a | Member lifecycle: disable / offboard / erase (§2) | this RFC's first PR |
| W6 | Materialisation correctness: group deactivate/delete, scope-rule deactivate/narrow/delete, group asset unassign recompute in the same transaction (database triggers, migration 001034); `ReconcileByAssetGroup` gets the real tenant (H6, M-2, M-3, M-4 refresh part) | in review |
| W1 | Exposure upsert never overwrites an out-of-scope or asset-less exposure for a restricted caller (H1) | planned |
| W2 | Scan actor integrity: clone/import set `CreatedBy`; a nil owner refuses; an inactive owner pauses and notifies (H2, H3) | planned (coordinated with the EASM scan-authorization work) |
| W4 | Pentest findings and PoC hidden from non-members on `/assets/{id}/findings` (H5) | planned |
| W3 | Simulations require act scope on targets (H4) | planned |
| W7 | Group modification cap; a suspended user cannot be added to a group | planned |
| W8 | Suppression create checks the asset's tenant and scope (M-10) | planned |
| W5, W9 | Small authz fixes and residual LOW items | planned |
| W10 | Docs drift (expiring grants are now planned, D4/A2) | planned |

P1 (W11–W20: one `decide()`, composite foreign keys, registry v2, on-behalf-of
jobs, `scope_version`, scoped aggregates, sensitivity classes), P2 (W21–W33:
view/act, expiry, guests, engagements, break-glass, service accounts, redacted
nodes, owner-as-approver, recertification, SCIM scope) and P3 (W34–W38) follow
research/21 §5.

## 4. Owner decisions (2026-10-04, all as recommended)

A1 assignee/approver row relation; A2 guest members with mandatory expiry and
expiry on role assignments; A3 no separate scan level yet; A4 delegated
admins author rules intersected with their act scope; A5 IdP groups → access
groups; A6 break-glass = scope only; A7 platform LLM off by default; A8 BU /
business-service criticality needs act on every linked asset; A9 minimal
outbound payloads; A10 auto-expire guests and ownerless grants; A11 custom
audit role needs full-data view; A12 MFA for full-data roles; A13 MSSP through
per-tenant guest memberships now. Member lifecycle (2026-10-04): disable,
offboard, erase as in §2.
