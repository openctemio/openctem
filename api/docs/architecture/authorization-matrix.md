# Authorization Matrix

This document describes the complete authorization model for the OpenCTEM API.

## Overview

The system uses a **two-layer authorization model**:

1. **Permission-based Authorization**: Fine-grained permissions (`resource:action`) embedded in JWT tokens
2. **Role-based Authorization**: Team roles (owner, admin, member, viewer) for team management

## Authorization Models

### Permission-based (JWT Claims)

Permissions are included in the access token and checked using `middleware.Require()`.

**The canonical permission list is code, not this document.** The single source
of truth is `permission.AllPermissions()` in
`pkg/domain/permission/permission.go`; `permission.IsValid()` /
`ParsePermission()` validate against it. As of this writing it defines
**169 permissions**, grouped by module. Rather than hand-mirror all 169 (which
would drift), the table below lists the module groups and the count each
contributes — derive the exact strings from `AllPermissions()`.

| Module group | Count | Example permissions |
|--------------|-------|---------------------|
| Core (dashboard, audit, settings) | 4 | `dashboard:read`, `audit:read`, `settings:read/write` |
| Assets | 11 | `assets:read/write/delete/import/export`, `asset_groups:*`, `components:*` |
| Findings | 32 | `findings:read/write/delete/assign/triage/status/export/approve/fix_apply/verify`, `exposures:*`, `suppressions:*`, `vulnerabilities:*`, `credentials:*`, `remediation:*`, `workflows:*`, `policies:*` |
| Scans | 22 | `scans:read/write/delete/execute`, `scan_profiles:*`, `sources:*`, `tools:*`, `tenant_tools:*`, `scanner_templates:*`, `secret_store:*` |
| Sensors | 9 | `sensors:read/write/delete`, `sensors:commands:read/write/delete`, `sensors:zones:read/write/delete` |
| Team | 20 | `team:*`, `members:*`, `groups:*`, `roles:*`, `assignment_rules:*` |
| Integrations | 18 | `integrations:read/manage`, `scm_connections:*`, `notifications:*`, `webhooks:*`, `api_keys:*`, `pipelines:*` |
| Settings (billing, SLA) | 6 | `billing:read/write/manage`, `sla:read/write/delete` |
| Attack Surface | 4 | `scope:read/write/delete`, `scope:exclusions:approve` |
| Validation (legacy) | 4 | `validation:read/write`, `pentest:read/write` |
| Pentest (granular) | 11 | `pentest_campaigns:*`, `pentest_findings:*`, `pentest_retests:*`, `pentest_templates:*`, `pentest_reports:write` |
| Compliance | 7 | `compliance_frameworks:*`, `compliance_assessments:*`, `compliance_mappings:*`, `compliance_reports:read` |
| Reports | 2 | `reports:read/write` |
| Threat Intel | 2 | `threat_intel:read/write` |
| AI Triage | 2 | `ai_triage:read/trigger` |
| CTEM (RFC-004/005) | 12 | `ctem_cycles:*`, `attacker_profiles:*`, `business_services:*`, `compensating_controls:*`, `priority_rules:*`, `verification_checklists:*` |
| **Total** | **169** | |

> There is **no `projects` module**. OpenCTEM has no `projects:*` permissions and
> no `/api/v1/projects/*` routes; the resource hierarchy is
> tenant → assets/components/findings. (This doc previously listed a phantom
> projects module — removed.)

### Role-based (Team Context)

Team roles are used for team management operations:

| Role | Level | Description |
|------|-------|-------------|
| `owner` | 4 | Team owner - full control, can delete team |
| `admin` | 3 | Team admin - manage members, invitations, settings |
| `member` | 2 | Team member - create/edit resources |
| `viewer` | 1 | Team viewer - read-only access |

## Middleware Stack

The authorization is implemented through a middleware chain:

```
Request
   │
   ▼
┌─────────────────────────────────────────┐
│ UnifiedAuth                              │ ← Validates JWT (local or OIDC)
│ - Extracts user ID, email, tenant ID     │
│ - Extracts permissions array             │
│ - Extracts role from claims              │
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ UserSync                                 │ ← Syncs user to local DB
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ RequireTenant (for JWT-tenant routes)    │ ← Validates tenant ID in token
│   OR                                     │
│ TenantContext (for URL-tenant routes)    │ ← Extracts tenant from path
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ RequireMembership (URL routes only)      │ ← Verifies team membership
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ Require(permission) / RequireTeamAdmin   │ ← Permission or role check
└─────────────────────────────────────────┘
   │
   ▼
Handler
```

## API Routes by Authorization Type

### Public Routes (No Auth)

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /ready` | Readiness check |
| `POST /api/v1/auth/register` | User registration (403 unless `AUTH_ALLOW_REGISTRATION=true` or a matching invitation token) |
| `POST /api/v1/auth/login` | User login |
| `POST /api/v1/auth/token` | Token exchange |
| `POST /api/v1/auth/refresh` | Token refresh |

### JWT-Tenant Routes (Tenant from Token)

These routes use the tenant ID embedded in the JWT access token.

They also accept a tenant `oct_` API key (`Authorization: Bearer oct_…` or
`X-API-Key`), **read-only** (GET/HEAD): the tenant comes from the key, the
permissions are the key's scopes narrowed to what its user holds now, the key
is never admin, and credential/account areas (`/api-keys`, `/scim-tokens`,
`/me`, `/notifications`, `/ws`, `/platform`, `/users`, …) refuse keys. Every
ungated route must refuse keys (`tests/unit/apikey_route_policy_test.go`).
Details: [api-keys.md](./api-keys.md).

#### Assets (`/api/v1/assets`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/assets` | `assets:read` |
| `GET /api/v1/assets/{id}` | `assets:read` |
| `POST /api/v1/assets` | `assets:write`. A name (or correlated address) that already exists in the organization is a 409 and changes nothing; `details.existing_asset_id` is set only when that asset is in the caller's data scope, otherwise the conflict is generic. Another organization's assets never match. Ingest keeps its own merge path. |
| `PUT /api/v1/assets/{id}` | `assets:write` |
| `DELETE /api/v1/assets/{id}` | `assets:delete` + data scope. Refused with 409 (`asset_has_findings`) while the asset has any finding (archive it instead); otherwise a soft delete, audited `asset.deleted` (see [asset-deletion.md](asset-deletion.md)) |

#### Business units (`/api/v1/business-units`)

| Endpoint | Gate |
|----------|------|
| `GET /api/v1/business-units` · `/{id}` | `assets:read` |
| `POST /api/v1/business-units` · `PUT /{id}` · `POST/DELETE /{id}/assets[/{assetId}]` | `assets:write` |
| `DELETE /api/v1/business-units/{id}` | **owner/admin only** (`RequireAdmin`, plus `assets:write`) |

> Deleting a business unit drops its asset links and detaches its child units
> for the whole organization, so it is owner/admin only (owner decision
> 2026-10-02); members keep creating, editing and linking assets.

#### Components (`/api/v1/components`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/components` | `components:read` |
| `GET /api/v1/components/{id}` | `components:read` |
| `POST /api/v1/components` | `components:write` |
| `PUT /api/v1/components/{id}` | `components:write` |
| `DELETE /api/v1/components/{id}` | `components:delete` |

#### Findings (`/api/v1/findings`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/findings` | `findings:read` |
| `GET /api/v1/findings/{id}` | `findings:read` |
| `POST /api/v1/findings` | `findings:write` |
| `DELETE /api/v1/findings/{id}` | `findings:delete` |
| `PATCH /api/v1/findings/{id}/status` | `findings:status` |
| `POST /api/v1/findings/{id}/triage` | `findings:triage` |
| `POST /api/v1/findings/{id}/duplicates` (mark the body's finding a duplicate of `{id}`, RFC-043) | `findings:triage`; also `findings:approve` when either finding is a false positive or risk acceptance (service check). Both findings must be in the caller's tenant and data scope (else 404) and on the same asset |
| `POST /api/v1/findings/{id}/assign` · `/unassign` · `/actions/assign-to-owners` | `findings:assign` |
| `POST /api/v1/findings/bulk/status` · `/bulk/assign` | `findings:bulk_update` |
| `POST /api/v1/findings/{id}/verify` | `findings:verify` |

> The finding **action** routes (status, triage, assign, bulk, verify) are gated on
> **precise granular permissions**, not the coarse `findings:write` (AUTHZ-05).
> `verify` is a separate permission from `status`/`triage` to keep
> **separation of duties** — the person who triages a finding should not be able to
> self-verify their own fix (AUTHZ B1, api#505). Migration `000217` backfilled the
> four granular perms onto every role that already held `findings:write`, so the
> tightening is honest-not-breaking: nobody lost an action they could perform before.

#### Exposures (`/api/v1/exposures`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/exposures` · `/{id}` · `/stats` · `/{id}/history` | `findings:read` |
| `POST /api/v1/exposures` · `/ingest` · `/{id}/resolve` · `/{id}/reactivate` · `PUT /{id}/ctem-id` | `findings:write` |
| `POST /api/v1/exposures/{id}/accept` · `/{id}/false-positive` | `findings:approve` |
| `DELETE /api/v1/exposures/{id}` | `findings:delete` |

> Accepted and false-positive are the dispositions a finding reaches only
> through the approval workflow (`FindingStatus.RequiresApproval`: request with
> `findings:write`, approve with `findings:approve`, never your own request).
> Exposures have no request/approve records, so these two transitions are
> gated on the approver permission itself: a `findings:write` holder (member)
> gets 403 and must ask an approver. The reason is kept in the exposure's state
> history. Unlike findings, an approver sets the state directly (no second
> person); a full request/approve flow for exposures would need its own
> records.

#### Scope exclusions (`/api/v1/scope/exclusions`)

An exclusion stops scans from touching whatever it matches, so it is a
two-person control:

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/scope/exclusions` · `/{id}` | `attack_surface:scope:read` |
| `POST /api/v1/scope/exclusions` · `PUT /{id}` · `POST /{id}/activate` · `/{id}/deactivate` | `attack_surface:scope:write` |
| `POST /api/v1/scope/exclusions/{id}/approve` · `/{id}/reject` | `attack_surface:scope:exclusions:approve` (owner, admin) |
| `DELETE /api/v1/scope/exclusions/{id}` · `POST /bulk/delete` | `attack_surface:scope:delete` |
| Taking an exclusion **in effect** out of effect: `/{id}/deactivate`, `DELETE`, bulk delete, or a `PUT` that moves `expires_at` earlier (a past date included) | in addition `attack_surface:scope:exclusions:approve`, and the caller must not be the requester (403 otherwise; research doc 15, L-07) |

- A new exclusion is created `pending` and is applied nowhere — not to scan
  target selection, not to `POST /scope/check`, not to coverage — until it is
  approved. Only an approved, `active`, unexpired exclusion is in effect
  (`in_effect: true` in the response); every consumer reads exclusions through
  `ExclusionRepository.ListActive`, which filters on exactly that.
- `scope:write` (held by members) only requests an exclusion.
  `attack_surface:scope:exclusions:approve` is granted to the owner and admin
  system roles (migration 000267); custom roles get it only when a tenant adds
  it.
- The requester (`created_by`) cannot approve their own exclusion, even when
  they hold the approve permission: 403, the same separation of duties as
  finding approvals.
- `reject` moves a pending exclusion to `rejected`; it can then be deleted but
  never approved or activated (409).
- `activate` only works on an approved exclusion (409 otherwise), so it cannot
  be used to skip the approval.
- Extending the window of an approved exclusion (a later `expires_at`, or
  removing it) sends it back to `pending`; shortening it keeps the approval.
- Removing protection is the same two-person control as granting it
  (`Exclusion.AuthorizeReduction`): deactivating, deleting or shortening an
  exclusion in effect needs the approve permission and someone other than the
  requester. Before, `scope:write` (a member default) could switch off the
  exclusion protecting a production host and then scan it. Changes to an
  exclusion not in effect (pending, inactive, rejected, expired) and edits of
  the reason keep their ordinary permission. The web console disables the
  switch for callers without the approve permission.
- Known gap: rows from before `created_by` was recorded have no requester, so
  the not-the-requester check cannot apply to them.
- Every change to a scope target or exclusion (create, update, delete, bulk
  delete, activate, deactivate, approve, reject) is one audit entry
  (`scope_target.*`, `scope_exclusion.*`) with the caller and the state before
  and after (RFC-040 §5.11). Changes that widen what is scanned (a new or
  re-activated target, a deleted or deactivated exclusion) are `high`
  severity. Tools and tenant tool configs (`tool.*`, secret-looking config
  values masked) and scanner templates (`scanner_template.*`, content hash
  only, never the content) are audited the same way. Refused changes write
  nothing.
- Exclusions that were `active` before migration 000267 were marked approved
  (`approved_by = 'system:pre-approval-grandfathered'` where none was recorded)
  so they stay in effect; inactive and expired ones need an approval to come
  back.

Where an exclusion in effect applies (RFC-042 F16). A failed exclusion
lookup stops the path; nothing is scanned or discovered without it (fail
closed):

| Path | Effect of a match |
|------|-------------------|
| Scan trigger (direct targets and asset-group members) | Target dropped from the run; a run whose every target is excluded is refused (`ALL_TARGETS_EXCLUDED`) |
| `POST /api/v1/pipelines/runs`, the `trigger_pipeline` workflow action | Target dropped from `context.targets`, the rest run; every target excluded is refused. The same run is refused (400 `TARGET_REFUSED`) for a target the scan target validator or zone routing refuses (private address outside every zone, loopback, link-local/metadata, uncovered). `scan_zone_id` in the caller's context is ignored and set from the routing |
| Tenable rolling coverage dispatcher | Asset skipped this rotation (its cursor still moves, so it does not hold the top of every batch); same for a target the validator or zone routing refuses. A batch stays in one zone and the command is stamped with it |
| Certificate Transparency discovery | An excluded watched domain is not queried; an excluded host gets no exposure |
| Ingest | A NEW asset matching by name, repository URL or address (and a root domain or resolved IP derived from one) is not added: counted as `assets_skipped_excluded`, named in the warnings, its findings skipped and never attached to another asset. An asset already in the inventory is not changed or deleted |

All of them go through the same matcher (`scope.Service.ExcludedTargets` /
`LoadExclusionMatcher`); the pipeline and coverage paths go through
`scan.Service.ResolveDispatchTargets`, which applies a scan's checks (scan
create's target validator, exclusions, zone routing) in one call.

#### Scan zones (`/api/v1/scan-zones`, RFC-023)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/scan-zones` · `/{id}` · `/coverage` | `sensors:zones:read` |
| `POST /api/v1/scan-zones` | `sensors:zones:write` |
| `PATCH /api/v1/scan-zones/{id}` | `sensors:zones:write` |
| `PUT` · `DELETE /api/v1/scan-zones/{id}/sensors/{sensorId}` | `sensors:zones:write` |
| `DELETE /api/v1/scan-zones/{id}` | `sensors:zones:delete` |

> Seeded by migration `000231`: owner and admin hold all three, member and
> viewer hold `sensors:zones:read` (RFC-023 D16). Object level: every query
> carries `tenant_id`, and `scan_zone_sensors` has composite foreign keys
> `(tenant_id, zone_id)` and `(tenant_id, sensor_id)`, so a zone or sensor of
> another tenant cannot be linked even by a wrong handler. See
> [scan-zones.md](scan-zones.md).

#### Sensors (`/api/v1/sensors`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/sensors` · `/stats` · `/{id}` · `/{id}/config-templates` · `/available-capabilities` · `/content-policy` | `sensors:read` |
| `POST /api/v1/sensors` · `PUT /{id}` · `POST /{id}/regenerate-key` · `/activate` · `/deactivate` · `/revoke` | `sensors:write` |
| `PUT /api/v1/sensors/content-policy` · `POST /content/refresh` · `POST /{id}/content/refresh` (scanner content, RFC-031) | `sensors:write` |
| `DELETE /api/v1/sensors/{id}` | `sensors:delete` |

> **Sensors and their keys are owner/admin only** (owner decision
> 2026-10-02). Every write above creates, rotates or invalidates a sensor
> credential (`rda_…`), so `sensors:write` and `sensors:delete` are held by
> owner and admin only; migration `000246` removed `sensors:write` from the
> member role (viewer never had it). Members and viewers keep `sensors:read`.
> Scan-zone sensor assignment (`sensors:zones:write`) hands out no key and was
> already owner/admin only (`000231`).
>
> **No custom role may carry them** (settings decision B1, 2026-10-04):
> `sensors:write`, `sensors:delete`, `sensors:commands:delete`,
> `sensors:zones:write` and `sensors:zones:delete` are admin-only
> (`pkg/domain/permission/admin_only.go`). The role service refuses them on
> create and update, whoever edits the role (400), and a trigger on
> `role_permissions` refuses a row that would put one on a custom role
> (migration `000945`, which also stripped them from existing custom roles and
> kept the report in `role_permissions_admin_only_stripped`). Custom roles
> keep the read permissions and `sensors:commands:write`.
>
> **Revoking a sensor goes through `POST /{id}/revoke` only**: `PUT /{id}`
> with `status: revoked` returns 400, so every revocation carries a reason and
> the Critical `sensor.revoked` audit event.

#### Audit log (`/api/v1/audit-logs`)

| Endpoint | Gate |
|----------|------|
| `GET /api/v1/audit-logs` · `/stats` · `/{id}` · `/resource/{type}/{id}` | `audit:read` (owner/admin only) |
| `GET /api/v1/audit-logs/user/{id}` | `audit:read`, **or `{id}` is the caller** (`RequirePermissionOrSelf`; user sessions only, not API keys) — everyone reads their own activity on `/account/activity` |
| `GET /api/v1/audit-logs/verify` | owner/admin (`RequireAdmin`) |
| `POST /api/v1/audit-logs/rebaseline` | **owner only** (`RequireOwner`) |

> The organization audit log (actor emails, IPs, every action) is owner/admin
> only: migration `000246` removed `audit:read` from member and viewer.
> Rebaseline overwrites the tamper-evident chain, so it is owner-only: an
> administrator must not be able to re-sign the chain over their own changes.

#### API keys (`/api/v1/api-keys`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/api-keys` · `/{id}` | `integrations:api_keys:read` — owner/admin see every key of the organization; anyone else sees **only their own keys** (another user's key reads as 404) |
| `POST /api/v1/api-keys` · `/{id}/revoke` | `integrations:api_keys:write` (owner/admin) |
| `DELETE /api/v1/api-keys/{id}` | `integrations:api_keys:delete` (owner/admin) |

> Keys belong to the user who minted them (`api_keys.user_id`). The list shows
> key names, scopes and last-used IPs, so a member or viewer is filtered to
> their own keys in the handler (`ownKeysOnly`).

#### SCIM tokens (`/api/v1/scim-tokens`)

| Endpoint | Gate |
|----------|------|
| `GET /api/v1/scim-tokens` · `GET/PUT /group-mappings` | owner/admin (`RequireAdmin`); a `PUT` that adds, changes or removes a mapping **to admin** is owner only (service check, 403) |
| `POST /api/v1/scim-tokens` · `DELETE /{id}` | **owner only** (`RequireOwner`) |

> A SCIM token can create, suspend and re-role every member, so minting and
> revoking one is the owner's decision (owner decision 2026-10-02). Which IdP
> group makes someone an administrator is the owner's decision too: only an
> owner-configured mapping grants or removes admin through SCIM (23b S-H1; see
> `scim-provisioning.md`).

#### Billing

`settings:billing:read` is owner/admin only (migration `000246` removed it from
member and viewer). There is no billing API route today; the permission gates
the billing page in the UI.

#### Leaked credentials (`/api/v1/credentials`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/credentials` · `/{id}` · `/{id}/related` · `/identities` · `/identities/{identity}/exposures` · `/stats` | `findings:credentials:read` |
| `POST /api/v1/credentials/import` · `/import/csv` · `/{id}/resolve` · `/reactivate` | `findings:credentials:write` |
| `POST /api/v1/credentials/{id}/accept` · `/{id}/false-positive` | `findings:credentials:write` **and** `findings:approve` (same dispositions as the exposure routes) |
| `POST /api/v1/credentials/{id}/reveal` | `findings:credentials:reveal` |

> **The leaked secret is reveal-only.** Read endpoints (here and under
> `/api/v1/exposures`) return `secret_masked` and `secret_fingerprint` (a
> keyed HMAC), never the plaintext. `findings:credentials:reveal` is held by
> owner and admin only (migration `000232`); viewer and member read the
> masked value. Every reveal writes `credential.revealed` to the audit log
> before the secret is returned, and the call answers 503 if the audit event
> cannot be written. At rest the secret is AES-256-GCM encrypted with
> `APP_ENCRYPTION_KEY` (`details.secret_value_enc`); the server seals legacy
> plaintext rows on start, and `cmd/encrypt-credentials` does the same offline.

#### Template sources and the secret store (`/api/v1/template-sources`, `/api/v1/secret-store`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/template-sources` · `/{id}` | `scans:sources:read` |
| `POST /api/v1/template-sources` · `PUT /{id}` · `/{id}/enable` · `/disable` · `/sync` | `scans:sources:write` |
| `DELETE /api/v1/template-sources/{id}` | `scans:sources:delete` |
| Secret store `GET` / `POST`,`PUT`,`POST /{id}/rotate` / `DELETE` | `scans:secret_store:read` / `:write` / `:delete` |

> **Secret store writes.** `PUT /secret-store/{id}` changes metadata only and
> leaves absent fields unchanged (`description: ""` clears it, `expires_at: null`
> clears the expiry; `expires_at` is RFC 3339 and must be in the future). The
> secret is replaced only by `POST /secret-store/{id}/rotate` (same credential
> type; `key_version` and `last_rotated_at` advance). Update, rotate (High),
> delete (High) and decrypt (High) are audited with the acting user, or a named
> system actor for a scheduled template sync. All lookups are by tenant and id.

> **A stored credential goes only where someone entitled to it pointed it.**
> A sync decrypts the source's `credential_id` and sends it to the source's
> URL (bearer/basic/API key, git token or SSH key, S3 keys). Members used to
> hold `scans:sources:write` (removed by migration `000262`, see rule 10) and
> still hold `scans:secret_store:write`; a custom role may carry both. The
> route gates alone would then let its holder send any stored secret to a
> server they run. `template.SourceService` therefore checks, on create and
> update:
> - **Binding** a credential (a new `credential_id`, or keeping one while the
>   destination changes) is allowed to tenant owners/admins and to the user who
>   stored that credential (`credentials.created_by`). Anyone else gets 403
>   `CREDENTIAL_BIND_FORBIDDEN`, and the attempt is audited as
>   `template_source.credential_attached` with result `denied`.
> - **Re-pointing** a source that carries a credential (git URL, HTTP URL, or
>   S3 endpoint/region/bucket/role ARN) without re-binding it in the same request
>   **drops the credential**, audited as `template_source.credential_detached`
>   (`reason: destination changed`). An S3 source cannot exist without its
>   keys, so re-pointing one needs the owner/admin to re-bind.
> - Every successful bind is audited as `template_source.credential_attached`
>   (severity high) with the credential id/name and the destination host.
>
> The secret store has no per-credential host allowlist; the binding check
> above is the control. Sources bound before this check existed keep their
> credential until they are next re-pointed.
>
> Templates synced or uploaded are validated before use. For Nuclei, the
> `code`, `javascript` and `headless` protocols are refused on the **parsed**
> document (`execProtocolKey`), so JSON, flow-style YAML, escaped or
> differently-cased keys cannot hide them.

#### Scans and commands: secret-looking config values

| Endpoint | Permission Required | `scanner_config` secrets |
|----------|---------------------|--------------------------|
| `GET /api/v1/scans` · `/{id}` · `/{id}/export` | `scans:read` | masked (`********`) unless the caller has `scans:write` |
| `GET /api/v1/commands` · `/{id}` | `commands:read` | `payload` masked the same way unless the caller has `scans:write` |
| `PUT /api/v1/scans/{id}` | `scans:write` | a `********` where the stored value would be masked keeps the stored value |

> Masked values are exactly those listed in `scanner_config_warnings`
> (`pkg/domain/scan/config_secrets.go`, `config_redact.go`). Owners and
> admins pass `scans:write` through the usual bypass. Sensor command claims
> are not user responses and carry the real values.

#### Vulnerabilities (`/api/v1/vulnerabilities`) - Global

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/vulnerabilities` | `vulnerabilities:read` |
| `GET /api/v1/vulnerabilities/{id}` | `vulnerabilities:read` |
| `GET /api/v1/vulnerabilities/cve/{cve_id}` | `vulnerabilities:read` |
| `POST /api/v1/vulnerabilities` | `vulnerabilities:write` |
| `PUT /api/v1/vulnerabilities/{id}` | `vulnerabilities:write` |
| `DELETE /api/v1/vulnerabilities/{id}` | `vulnerabilities:delete` |

#### Dashboard (`/api/v1/dashboard`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/dashboard/stats` | `dashboard:read` |
| `GET /api/v1/dashboard/stats/global` | `dashboard:read` |

### URL-Tenant Routes (Tenant from URL)

These routes require the tenant ID in the URL path and use database-based membership verification.

#### Teams (`/api/v1/tenants`)

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/tenants` | Any authenticated |
| `POST /api/v1/tenants` | Any authenticated |
| `GET /api/v1/tenants/{tenant}` | Any authenticated |

> These responses carry the tenant's `settings` map, which every member can
> read. Secrets stored in settings (`api.webhook_secret`, `ai.api_key`, and any
> key whose name marks it as a secret) are **write-only**:
> `tenant.RedactSettings` removes them and adds `<key>_configured: true|false`.
> The webhook signing secret is set with the owner-only
> `PATCH /api/v1/tenants/{tenant}/settings/api`.

#### Team Management (`/api/v1/tenants/{tenant}`)

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/tenants/{tenant}/members` | Team viewer+; **emails, last sign-in and second-factor status only for owner/admin** (others get ids, names, avatars, roles; `search` matches names only) |
| `GET /api/v1/tenants/{tenant}/invitations` | Team viewer+ |
| `PATCH /api/v1/tenants/{tenant}` | Team admin+ |
| `POST /api/v1/tenants/{tenant}/members` | Team admin+ |
| `PATCH /api/v1/tenants/{tenant}/members/{id}` | Team admin+; **owner only when the target is an administrator** |
| `POST /api/v1/tenants/{tenant}/members/{id}/suspend` · `/reactivate` | Team admin+; **owner only when the target is an administrator** |
| `DELETE /api/v1/tenants/{tenant}/members/{id}` | Team admin+; **owner only when the target is an administrator**. An **offboarding** with no reassignment plan (member lifecycle, RFC-050): 409 `reassignment_required` when the member owns work; the membership row is never deleted |
| `GET /api/v1/tenants/{tenant}/members/{id}/access-report` | Team admin+ (`members:read`): what the member holds and owns |
| `POST /api/v1/tenants/{tenant}/members/{id}/offboard` | Team admin+ (`members:write`); **owner only when the target is an administrator**; reassignment targets must be active members of the same organization |
| `POST /api/v1/tenants/{tenant}/members/{id}/erase` | **Team owner only**; only after offboarding and when the person belongs to no other organization |
| `POST /api/v1/tenants/{tenant}/members/{id}/reset-2fa` | Team admin+; **owner only when the target is an owner or administrator**; never the caller themself; the caller needs the same authority in **every other organization** the target belongs to (the factor is account-wide). See `user-two-factor-authentication.md` › Recovery |
| `POST /api/v1/tenants/{tenant}/invitations` | Team admin+ |
| `DELETE /api/v1/tenants/{tenant}/invitations/{id}` | Team admin+ |
| `POST /api/v1/tenants/{tenant}/users` | Team admin+ (creates an account + one-time set-password link; RFC-025) |
| `POST /api/v1/tenants/{tenant}/users/{userId}/setup-link` | Team admin+ (only an unused account that belongs to this organization only). The link takes the account over before its first sign-in, so an **owner or admin target needs an owner**, and the caller must be able to grant every role the target holds (403 otherwise). The platform console never uses this route: it issues a new organization's owner link under the first-owner rule (emailed only, see Organizations). |
| `PATCH /api/v1/tenants/{tenant}/settings/security` | **Team owner only** (refuses an IP allowlist that excludes the caller's IP) |
| `DELETE /api/v1/tenants/{tenant}` | **Team owner only** |

> **Peer administrators are the owner's** (owner decision 2026-10-02, AUTHZ
> B3). Changing the role of, suspending, reactivating or removing a member who
> is an administrator (or owner) needs the caller to be the owner; anyone else
> gets 403 (`TenantService.authorizeMemberChange`). The same holds on the RBAC
> paths (`/api/v1/users/{id}/roles`, assign/remove/bulk): only an owner may
> change another administrator's role set (`grant_guard.go`). Administrators
> still manage members and viewers, and may change their own membership. SCIM
> (no human actor) is not a peer and keeps its own rules: it grants or removes
> admin only through a mapping the owner configured, and the role changes a
> mapping save causes run as the person who saved it.
>
> **Only the owner makes someone an administrator** (settings decision B2,
> 2026-10-04). Adding a member as `admin`, changing a member's role to
> `admin`, inviting someone or creating a user with the system admin role, and
> granting the system admin role on the RBAC paths (assign, set, bulk) all need
> the caller to be the owner; anyone else gets 403
> (`TenantService.authorizeAdminPromotion`,
> `RoleService.authorizeAdminPromotion`). An administrator who edits their own
> role set may keep the admin role they hold. Step-up re-authentication for
> this action is planned with the step-up primitive (settings plan P1-01).
> A membership role change is one transaction (label and system role
> together).
>
> **Granting roles** (invitations and created users) is anti-escalation checked:
> a caller who is not an organization admin may grant only roles whose
> permissions they hold, and the owner role is never grantable. The membership
> role is derived from the granted RBAC roles (`member` if they include the
> system member/admin role, else `viewer`) and the granted roles become the
> user's exact role set, so the `tenant_members` → `user_roles` trigger cannot
> add more.

#### Invitations (`/api/v1/invitations`)

| Endpoint | Required Role |
|----------|---------------|
| `POST /api/v1/invitations/lookup` | Public (token in the body, rate limited) |
| `POST /api/v1/invitations/decline` | Public (token in the body, rate limited) |
| `POST /api/v1/invitations/accept` | Any authenticated (email must match) |
| `POST /api/v1/invitations/accept-with-refresh` | Refresh token (email must match) |

The `/api/v1/invitations/{token}/...` paths are deprecated aliases of these (RFC-041) with the same chains.

### User Routes (`/api/v1/users`)

| Endpoint | Required Auth |
|----------|---------------|
| `GET /api/v1/users/me` | JWT |
| `PUT /api/v1/users/me` | JWT |
| `PUT /api/v1/users/me/preferences` | JWT |
| `GET /api/v1/users/me/tenants` | JWT |
| `POST /api/v1/users/me/change-password` | JWT (local auth only) |
| `GET /api/v1/users/me/sessions` | JWT (local auth only) |
| `DELETE /api/v1/users/me/sessions` | JWT (local auth only) |
| `DELETE /api/v1/users/me/sessions/{id}` | JWT (local auth only) |

### Build version

| Endpoint | Required Auth |
|----------|---------------|
| `GET /api/v1/version` | JWT (any signed-in user; no `oct_` keys) |
| `GET /api/v1/admin/version` | Console session (any admin role) |

The running build (`version`, `commit`, `build_time`, `channel`) for Help >
About. Deliberately not on the public `/health`: an unauthenticated client
cannot fingerprint the build. Release images stamp it with `-ldflags` from the
tag; the dev container's air build stamps `<highest tag>-dev`; an unstamped
binary reads the checkout's `.git` (`pkg/version`).

### Real-time WebSocket (`/api/v1/ws`)

The socket opens the tenant's real-time stream, so the upgrade is held to the
same tenant gates as any session tenant route ([RFC-045](../rfcs/RFC-045-websocket-auth.md)).

| Endpoint | Required Auth |
|----------|---------------|
| `GET /api/v1/ws` | Session access token from the `auth_token` cookie (browser, same origin) or `Authorization: Bearer`; no `oct_` keys. Tenant chain: revoked-session check, SSO enforcement, organization IP allowlist, `RequireTenant`, active membership, read rate limit (`realtimeMiddlewares`). Origin must be in `CORS_ALLOWED_ORIGINS` (exact match); a cookie-authenticated upgrade without an Origin is refused |

- No credential travels in the URL. The single-use ticket
  (`GET /api/v1/auth/ws-token`) and the short-lived JWT fallback were
  removed; a `?ticket=` parameter is ignored.
- A suspended member, a user who is not a member of the token's tenant, a
  caller outside the organization's IP allowlist (403 `IP_NOT_ALLOWED`), a
  password session in an SSO-enforced tenant and a revoked session are
  refused at the upgrade.
- The browser always opens the socket on the UI's own origin: the gateway
  routes `/api/v1/ws` to the API, and the web server (`server-with-ws.mjs`,
  all-in-one image and Helm) or `next dev` forwards it with the `Cookie` and
  `Origin` headers. Cross-site WebSocket deployments are not supported; serve
  the path on the UI origin.
- After the upgrade, every channel subscription is authorized by
  `websocket.Hub.defaultAuthorize` against the connection's user and tenant
  (own `user:{tenant}:{user}` only, own `tenant:{id}` only, permission +
  data scope for `finding:`/`triage:`, `scans:read` for `scan:`).
- **The socket is bound to its session** ([RFC-045](../rfcs/RFC-045-websocket-auth.md)).
  The server closes it with code `4401`:
  - at the expiry of the access token it was opened with, and at most 15 minutes
    (less up to 60 s of jitter) after it opened, so gates that publish no
    event (IP allowlist edits, SSO enforcement, data scope) are re-applied
    on the reconnect;
  - when its session is signed out or revoked: every path that writes the
    session revocation store (logout, sign out device / everywhere,
    password change, 2FA enrolment, user or member suspension, session-limit
    eviction, OIDC back-channel logout) also publishes on Redis `ws:revoke`,
    and every API instance closes its matching sockets;
  - when the user's membership or role in its tenant changes (permission
    version bumped or dropped: role assigned, removed or redefined, member
    role changed, member removed or suspended).
- Limits: 10 sockets per user per instance (more → `4429`), 50 subscriptions
  per socket, 10 messages/s (burst 60; abuse → `1008`), 4 KiB frames, 60 s
  read deadline with server pings. Nothing is delivered after the server's
  close frame.

### Platform Admin Routes (`/api/v1/admin/*`)

Platform admin routes are for OpenCTEM operators, NOT tenant users. They
authenticate **only** with a **console session** (RFC-022: `/login` password
sign-in + mandatory TOTP, server-side session in the `admin_session` cookie,
scoped to `/api/v1/admin`; cookie-authenticated writes must pass the
`admin_csrf` double-submit check). There are **no admin API keys**: an
`X-Admin-API-Key` or `Authorization: Bearer` header authenticates nothing here,
so every admin action has passed TOTP. The session resolves to an
`admin_users` row with a platform role: `super_admin` > `ops_admin` >
`readonly`. The tenant JWT never authenticates these routes, and the admin
session never reaches tenant routes.

Authorization is enforced at the **route layer** in
`internal/infra/http/routes/admin.go` via `AdminAuthMiddleware.RequireRole(...)`
— not in the handlers.

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/admin/auth/validate` | any admin |
| `POST /api/v1/admin/auth/session`, `/mfa` | public (rate-limited; needs the `/login` refresh cookie, then TOTP) |
| `POST /api/v1/admin/auth/logout` | public (ends the caller's own console and `/login` session) |
| `POST /api/v1/admin/auth/password` | any admin (the only write allowed while `password_change_required`) |
| `GET /api/v1/admin/auth/idp` | public (enabled + display name of the platform IdP, nothing else) |
| `POST /api/v1/admin/auth/idp/start`, `/idp/callback` | public (token-exchange rate limit, 20/min; state bound to the `admin_idp` cookie, single use) |
| `POST /api/v1/admin/administrators` | **super_admin** (audited; `break_glass` audited high) |
| `POST /api/v1/admin/users/{id}/reset-credentials` | **super_admin** (audited; not self) |
| `POST /api/v1/admin/users/{id}/break-glass-test` | **super_admin** (audited; not the break-glass account itself) |
| `DELETE /api/v1/admin/users/{id}/idp-binding` | **super_admin** (audited high) |
| `GET/PUT/DELETE /api/v1/admin/platform-idp` | **super_admin** (writes audited high; secret never returned) |
| `GET /api/v1/admin/users` | **super_admin** |
| `GET /api/v1/admin/users/{id}` | **super_admin** |
| `PATCH /api/v1/admin/users/{id}` | **super_admin** (audited) |
| `DELETE /api/v1/admin/users/{id}` | **super_admin** (audited) |
| `GET /api/v1/admin/audit-logs` (+ `/stats`, `/{id}`) | any admin (readonly ok) |
| `GET /api/v1/admin/target-mappings` (+ `/stats`, `/types`, `/{id}`) | any admin |
| `POST/PATCH/DELETE /api/v1/admin/target-mappings` | **ops_admin+** (rate-limited, audited) |
| `GET /api/v1/admin/tenants/{tenantId}/audit-chain` | any admin (classifies the organization's audit hash-chain; read-only) |
| `POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline` | **super_admin** + a fresh console TOTP code in the body (step-up; a wrong code counts toward lockout). Refused 409 when a break is unexplained or the chain changed since the reviewed classification. Audited high in `admin_audit_logs` and as `audit.chain_rebaselined` in the organization's log |

> The admin roster (`/admin/users`) is super_admin-only for reads as well as
> writes: it exposes admin emails and last-used IPs, so listing
> it is itself a privileged operation.

### SSO / identity-federation setup (platform administrator)

SSO **setup** for an organization (SAML, OIDC identity providers, verified
domains, SSO enforcement) is a platform-administrator operation, modeled on
Tenable Security Center's system-level Configuration. It lives only under the
admin realm, `/api/v1/admin/tenants/{tenantId}/sso/*` (next section). The former
tenant-context routes `/api/v1/settings/{saml,identity-providers,verified-domains}`
and the `PLATFORM_ADMIN_EMAILS` flag that guarded them were removed; no tenant
role, however high, can reach SSO setup. The SSO **login** flow
(`/api/v1/auth/sso/*`, `/api/v1/auth/saml/{org}/*`) is public and unchanged.

### Platform administrator identity (RFC-022)

A platform administrator is a `users` account linked to an `admin_users` row
(`admin_users.user_id`) that holds the role (`super_admin` > `ops_admin` >
`readonly`), the TOTP second factor and the admin audit trail. It signs in on the
normal `/login`, then `POST /api/v1/admin/auth/session` (refresh-token cookie)
and `POST /api/v1/admin/auth/mfa` open a console session. Rules:

- **Belongs to no organization.** A trigger on `tenant_members` rejects a
  membership for a linked account (SQLSTATE 23514, surfaced as 409), and an
  account with memberships cannot be linked. This is what keeps a tenant
  role and the platform role from ever meeting in one principal.
- **Password sign-in only.** A session created by SSO, SAML or a social provider
  cannot open the console, so no organization's IdP can authenticate an
  administrator.
- **TOTP always.** The `/login` session alone reaches nothing under
  `/api/v1/admin/*`; only a verified console session does (there are no
  admin API keys).
- Provisioning is `POST /api/v1/admin/administrators` (super admin), or
  `bootstrap-admin` for the first one and its break-glass backup. Rows without
  a `user_id` (former API-key identities) were deactivated by migration 000227.
- **Temporary password gate.** A provisioned account has
  `password_change_required`; a password-authenticated console session can then
  call only `GET /auth/validate` and `POST /auth/password` (403
  `PASSWORD_CHANGE_REQUIRED` otherwise).

#### Break-glass administrators and the platform IdP (RFC-022 revision 4)

- **Platform IdP** (`platform_identity_provider`, one OIDC provider, not
  tenant-scoped) is the only IdP that can open the console, and only for an
  administrator that already exists: matched by bound (`iss`, `sub`), or on
  first sign-in by verified email, then bound. No JIT creation. The console TOTP
  is still required after it unless a super admin trusts specific `acr`/`amr`
  values. Organization IdPs still cannot open the console.
- **Require IdP** refuses the local password path (`/auth/session`) for every
  administrator except break-glass ones.
- **Break-glass** administrators are local `super_admin`s that can never be
  bound to the IdP (database `CHECK`), are exempt from "require IdP", and every
  sign-in is audited high + alerted (`alert=break_glass_sign_in` + email).
- **Invariant** (server-side, under an advisory lock): at least one active,
  linked `super_admin` who can sign in locally always remains — while "require
  IdP" is in force, at least one break-glass `super_admin`. Delete, deactivate,
  demote and unmark that would break it return 409, as does turning on "require
  IdP" without one.

### Organizations — platform admin cross-tenant (RFC-022 Phase 2)

Under the admin realm (console session), never tenant-permission
gated. Organization-scoped SSO routes reuse the tenant SSO handlers through
`AdminTenantScope`, which checks the organization exists, sets it as the request
tenant, and **clears the user id** (the principal is the admin identity, not an
organization member, and those handlers write `created_by` columns that
reference `users(id)`). Writes are
recorded in `admin_audit_logs`, and in the organization's own audit log with
`actor_email = platform-admin:<email>`, `actor_id` NULL and `actor_ip` the
resolved client IP (forwarding headers only from a trusted proxy). The
organization's log gets: `sso.saml_config_updated` / `_deleted`,
`sso.identity_provider_created` / `_updated` / `_deleted`,
`sso.verified_domain_added` / `_verified` / `_deleted` (severity high; written
by the SAML, SSO and verified-domain handlers), `tenant.settings_updated` for
SSO enforcement, and `user.created` for console-created users. Client secrets
and certificates are never logged — an IdP update records
`client_secret_changed`, a SAML save records the certificate's SHA-256.

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/admin/tenants` (+ `/{tenantId}`) | any admin |
| `POST /api/v1/admin/tenants` | **ops_admin+** (audited; creates the owner's account when `owner_email` has none) |
| `GET /api/v1/admin/tenants/{tenantId}/users` | any admin |
| `POST /api/v1/admin/tenants/{tenantId}/users` | **ops_admin+**, **bootstrap only**: creates the first owner of an organization with no owner, active or suspended, nothing else (409 otherwise). With `"recovery": true`: **super_admin** only (403 otherwise), for an organization whose owners are all suspended (409 while one is active), link emailed only (400 without email). Audited in `admin_audit_logs` (`organization.user_create` / `organization.owner_recovery`) and the organization's audit log |
| `GET /api/v1/admin/tenants/{tenantId}/sso/{saml,identity-providers,verified-domains,enforcement}` | any admin |
| `PUT/POST/DELETE` on those SSO resources | **super_admin** (audited). SAML `PUT` and identity-provider `POST`/`PUT` on an organization **with an owner** only store a pending change (202) that an owner must approve; see below |
| `GET /api/v1/admin/tenants/{tenantId}/sso/changes` | any admin (what is waiting for the owner) |

**First-owner bootstrap** (owner decision 2026-10-02, RFC-022 revision 5).
The platform administrator belongs to no organization and cannot put a person
of its choosing into one: `POST /admin/tenants/{tenantId}/users` creates only
the first owner of an organization that has no owner, active or suspended (checked and
inserted in one transaction under a per-organization advisory lock, so two
requests cannot create two owners), and answers 409 once an owner exists — the
owner and its administrators add users themselves. The account is created
without a password; the owner sets one through a one-time link, so the
administrator never knows it and the owner's first sign-in is with a password
they chose. The link is **emailed when the organization can send email** and is
then never returned (a failed send reports `email_failed`; the owner uses
forgot-password). Only when email cannot be sent at all is `setup_token`
returned once: there is no other way to reach the new owner, and nobody in the
organization can invite them yet. The same delivery rule applies to the owner
created with `POST /admin/tenants`. Each is written to the organization's audit
log (`user.created`, `bootstrap_owner: true`, actor `platform-admin:<email>`).

**Owner recovery** (RFC-022 revision 7). A suspended owner still owns the
organization, so the bootstrap is refused. When every owner is suspended, a
**super_admin** may send `"recovery": true` to create a new owner. Other
console roles get 403, an active owner means 409, and an organization that
cannot send email gets 400. The link is emailed only, never returned. It is
audited as `organization.owner_recovery` (admin log, high, refusals included)
and as `user.created` with `owner_recovery: true` at critical severity in the
organization's log.

**SSO changes wait for an owner** (owner decision 2026-10-02, RFC-022
revision 8). A platform administrator who could set an organization's SAML
certificate or OIDC client could sign in as any of its members, so on an
organization that has an active owner those writes are stored in
`sso_pending_changes` and the live config is untouched until an owner decides:

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/tenants/{t}/settings/sso/changes` | **owner** (`RequireTeamOwner`) |
| `POST /api/v1/tenants/{t}/settings/sso/changes/{id}/approve` | **owner** (`RequireTeamOwner` + the service re-checks active ownership in the database); applies the change and marks it approved in one transaction; audited `sso.change_approved` |
| `POST /api/v1/tenants/{t}/settings/sso/changes/{id}/reject` | **owner** (same gates); audited `sso.change_rejected` |

Administrators, members and viewers of the organization get 403; an owner of
another organization gets 404 (the change is looked up in the caller's
organization) or 403 (naming the other organization fails the ownership
check). An expired change (7 days) answers 410; one already decided or
superseded by a newer submission answers 409. Every active owner is notified
in-app (`sso_change_pending`) and by email when SMTP is configured, without
secrets. **Bootstrap exception:** an organization with no active owner gets the
change applied directly. Deletes, SSO enforcement and verified domains are not
gated (none adds a way in).

**Tenant-side counterparts:**
- `PATCH /tenants/{t}/settings/security` refuses `sso_enforced` with 403.
  Enforcement is set only through `PUT /admin/tenants/{tenantId}/sso/enforcement`,
  which keeps the "usable SSO path required" guard.
- With `TENANT_CREATION_MODE=admin_only` (the default; anything but
  `self_service` counts), both self-service creation paths
  (`POST /api/v1/tenants` and `POST /api/v1/auth/create-first-team`) return
  403. Only `POST /admin/tenants` (and `bootstrap-admin -org-*` at install)
  creates organizations. The mode is published
  as `tenant_creation_mode` on the public `GET /api/v1/auth/providers`.

### Metrics Endpoint (`GET /metrics`)

`/metrics` (Prometheus) is **not public by default**. It is gated by
`MetricsConfig`:

| `METRICS_PUBLIC` | `METRICS_TOKEN` | Behavior |
|------------------|-----------------|----------|
| `false` (default) | set | Requires `Authorization: Bearer <token>` (or `X-Metrics-Token`). Missing/wrong → 404 |
| `false` (default) | empty | Endpoint disabled (fail closed, 404) |
| `true` | — | Open, no auth (legacy; use only when firewalled to an internal scrape network) |

`/health` and `/ready` remain public. Configure the scraper's bearer token to
match `METRICS_TOKEN`.

## Organization access policy (RFC-025)

Two per-organization policies (`Security.AllowedDomains`, `Security.IPWhitelist`,
owner-managed) are enforced, not just stored. See
[user-onboarding.md](./user-onboarding.md).

- **Allowed email domains** gate every way into the organization: invitations
  (create and accept), invited registration, administrator-created users,
  `AddMember`/SCIM, and SSO just-in-time provisioning.
- **IP allowlist**: `middleware.IPAllowlistGate` runs on every user-token
  request (in `buildBaseMiddlewares` for the token's organization and after
  `RequireMembership` on `/tenants/{tenant}` for the URL organization), and on
  every tenant `oct_` API-key request on the REST API. Not applied to sensor
  keys, the MCP endpoint, the admin console, or public routes. 403 `IP_NOT_ALLOWED`; lookup errors fail closed; client IP from
  `httpsec.ClientIP` (trusted proxies only).
- **Self-registration** (`POST /auth/register`) is off unless
  `AUTH_ALLOW_REGISTRATION=true`; a pending invitation for the same email opens
  it for that person only.

## Data scope (Layer 2: access groups)

Scans act on assets, so the data scope also limits scan targets: a restricted
member scans only assets in their scope, and an unrestricted actor's free-text
targets must match a scope target (decision D9). See
[active-probe-gate.md](active-probe-gate.md#act-scope-who-may-scan-what).

Permissions decide what *kind* of thing a member may do; the data scope decides
*which* assets — and so which findings, exposures and other asset-bound rows —
they may see and change. Scope rows live in `user_accessible_assets`, computed
from exactly two sources:

| Source | Managed with | Rows |
|---|---|---|
| **Group assignment**: the assets assigned to the user's active groups | `team:groups:write` (Groups → Assets, scope rules, or a *group* owner on an asset's Owners tab) | `asset_owners` rows with `group_id` × `group_members` |
| **Explicit grant**: one user, one asset | `team:groups:write` (`/api/v1/assets/{id}/access-grants`) | `asset_access_grants` (migration `000372`) |

**Being an owner is not an access grant** (owner decision O1, 2026-10-03).
Naming a user as an owner of an asset, in any RACI role or through the
`owner_ref` email match, is an assignment (accountability, finding
assignment, notifications) and never changes what that user can see. Before
O1 it did: `assets:write` alone could narrow a member who saw everything
to that one asset, or widen one who saw nothing. Migration `000372` turned every such
owner-derived access row into an explicit grant (source `migration`), so
nobody lost an asset at the upgrade; administrators review and revoke them
on the asset's Owners tab (*Direct access*). A group owner remains the
group's assignment, which is why adding or removing one needs
`team:groups:write` on top of `assets:write`/`assets:delete`.

| Route | Gate |
|---|---|
| `GET /api/v1/assets/{id}/access-grants` | `team:groups:read` + data scope on the asset |
| `POST /api/v1/assets/{id}/access-grants` (`{"user_id"}`) | `team:groups:write`; the asset and the user must belong to the caller's organization (404 otherwise, the same answer for both); 403 when the user is the caller (no self-grant, so access held through a group cannot be turned into a personal grant before leaving it); 409 when the grant exists; audited `asset.access_granted` |
| `DELETE /api/v1/assets/{id}/access-grants/{grant_id}` | `team:groups:write`; the grant must be on that asset of the caller's organization (404); audited `asset.access_revoked`. The user keeps the asset only if a group still holds it |
| `POST /api/v1/assets/{id}/owners` with `group_id` · `DELETE /api/v1/assets/{id}/owners/{id}` of a group owner | `assets:write` / `assets:delete` **and** `team:groups:write` (403 otherwise) |
| `POST /api/v1/groups/{g}/assets` · `/assets/bulk` · scope rules | `team:groups:write`; the group must be in the caller's organization, and each asset must be a live asset of the **group's** organization. A single assign answers 404 for a foreign, deleted or unknown asset id alike; a bulk assign counts them as failed |

**You can only hand out scope you hold** (owner decision D13, research doc 15
L-09). A custom role with `groups:write` / `groups:members` (a "team lead")
could otherwise widen anyone's scope, their own included:

| Change | A caller whose own scope is restricted |
|---|---|
| `POST /groups/{g}/assets`, `/assets/bulk` | only assets in their scope; another asset answers 404 (bulk: counted as failed) |
| `POST /groups/{g}/members` | only when every asset the group holds is in their scope (403 otherwise); never themselves: joining a group needs full data access (admin or a `has_full_data_access` role), 403 otherwise |
| `POST/PUT /groups/{g}/scope-rules` | refused (403): a rule adds every matching asset, now and later, so it cannot be capped when it is written |
| `/assets/{id}/access-grants`, a group owner on `/assets/{id}/owners` | already limited to assets the caller sees (route guard on `/assets/{id}`) |

"Restricted" is the enforcer's decision (`Enforcer.Delegable`): an admin, a
full-data role and an internal call are unrestricted. `POST /groups/{g}/members` also refuses
(404) a user who is not a member of the organization (L-14).

**Group asset rows are same-tenant only.** `asset_owners` has no `tenant_id`,
so every insert path (`CreateAssetOwner`, the bulk and scope-rule inserts) is an
`INSERT … SELECT` joined to the asset's tenant, every read of a group's assets
joins the asset to the group's tenant, and the access-refresh functions only
materialize assets of the group's tenant. Trigger `asset_owners_same_tenant`
(migration `000455`) refuses a cross-tenant group row from any writer, and the
same migration removed any such row written before (research doc 15, L-01).

**Every route has a data-scope class** (research doc 15 P1-3,
`tests/unit/route_scope_classification_test.go`). `dataSurfaceRegistry`
classifies each route by its longest path prefix: `scoped` (asset-derived rows
limited to the caller's scope), `partial` (rows scoped, some counts
tenant-wide), `gap` (asset-derived and not yet scoped; the note cites the
research finding that tracks it), `separate` (another access model, e.g.
pentest membership), `config` or `system`. A new route without a class, a
stale entry, or a gap without a tracking reference fails CI. When you add a
route, classify it there in the same PR; when you close a gap, move its entry
to `scoped`.

**Who is restricted:**

| Caller | Sees |
|---|---|
| Owner / admin (`IsAdmin`) | everything in the tenant |
| A user holding a role with `has_full_data_access` (the system Owner and Administrator roles, or a custom role such as a "Global Reader") | everything in the tenant, whatever their group rows; **not** through an API key |
| Internal calls with no user (jobs, sensors, ingest) | everything in the tenant |
| Member with ≥ 1 scope row | only their in-scope assets |
| Member with no scope row | **nothing**, in every organization |

**Full data access is the Layer 2 bypass** (owner decision D3, research doc
15 L-11). `roles.has_full_data_access` used to be stored, shown in the role
editor ("Access all data regardless of group membership") and guarded on
grant, but nothing read it. Now `datascope.Enforcer.ResolveFor` checks it
(`DataScopeRepository.HasFullDataRole`, one indexed query per resolve) before
the scope rows, and the older list paths (asset list, stats and facets,
finding list and stats, asset and finding by id) use the same decision
through `Enforcer.FullData`. A lookup error restricts. A request made with an
API key never gets full data from its holder's role; a dedicated full-data key
is future work (research doc 15, §5.7). Granting the flag is capped by the
grant guard (you cannot give what you do not hold). A view-only level is part
of the view/act work (P2).

**No "see everything" mode** (owner decision D2, research doc 15 L-04; owner
signoff 2026-10-04 to finish the retirement). A member with no scope row and
no `has_full_data_access` role sees nothing, everywhere: lists, searches,
counts, exports, dashboards, reports, notifications and WebSocket channels,
and every by-id read answers 404. There is no per-organization switch back.

- Before, `tenants.members_without_group_see` (migration `000247`) let an
  organization show such members **everything** (fail-open; every
  organization created before `000247` started that way). In fail-open
  organizations a member who lost their last scope row (a tag change, an
  emptied group, a deleted asset) silently widened to the whole tenant.
- The enforcer, the older list paths (asset list, stats and facets, finding
  list, search and stats, finding groups) and the real-time push recipients no
  longer read the column: the SQL predicate is always
  `asset_id IN (SELECT asset_id FROM user_accessible_assets …)`, and a user
  scope without a tenant matches nothing. The `NOT EXISTS … OR` bypass, the
  per-tenant policy cache (which also treated a read failure as
  `everything`) and `DataScopeStrict`/`ScopeStrict` are gone.
- An unparseable acting user on the finding list or stats is refused instead
  of falling through to tenant-wide results.
- The switch surface is gone: `GET`/`PATCH /api/v1/tenants/{tenant}/settings/data-scope`,
  the `GET /api/v1/organization/settings/data-scope/impact` pre-flight report,
  the web console's "see everything" banner and the Settings → Teams card.
  Settings → Teams states the rule instead.
- The column itself is retired in steps:
  1. no code reads it for visibility;
  2. migration `000910` (expand) stores `nothing` in every organization, keeps
     the `nothing` default and replaces the CHECK with
     `members_without_group_see = 'nothing'`, so `everything` can never be
     stored again; its down migration restores the `000247` CHECK and does
     **not** flip any organization back;
  3. **follow-up (contract), after the release that ships `000910`:** drop the
     column and its CHECK (`ALTER TABLE tenants DROP COLUMN
     members_without_group_see`), once no deployed binary can still select
     it.

**One enforcement point.** `internal/app/datascope.Enforcer` resolves the
caller's scope (caller and admin flag come from the HTTP auth context, wired in
`cmd/server/services.go`) and is shared by every service. Nil-safe: an unwired
service is unrestricted. Out-of-scope by-id access returns **404**, never 403 —
the same answer as a missing row, so it is not an existence oracle; in bulk
results an out-of-scope id is reported exactly like an unknown id.

- **By-id routes:** `middleware.DataScopeGuard` runs last on every token-tenant
  chain (`buildTokenTenantMiddlewares`). Any request under
  `/api/v1/assets/{uuid}/**`, `/api/v1/findings/{uuid}/**`,
  `/api/v1/compliance/findings/{uuid}/**` or
  `/api/v1/verification-checklists/{uuid}` — read or write, the object or any
  sub-resource, including routes added later — is checked before the handler.
- **Bulk-by-id and id-in-body paths:** services filter with the same enforcer.
- **Grouped / by-filter finding queries** (`/findings/groups`, related CVEs,
  verify / reject-fix / fix-applied by filter, assign-to-owners):
  `FindingActionsService.visibleTo`
  applies the enforcer's scope and the findings list's pentest-membership rule;
  the group builder (`buildFilterWhere`) honors both filter fields with the
  list's meaning, and a rule without a tenant matches nothing. Remediation
  groups resolve the scope in `remediation.GroupService` and pass it to the
  key repository (`ListGroups`, `OpenFindingIDs`). Do not set
  `FindingFilter.DataScopeUserID` by hand in new code: use the enforcer
  (`Resolve` + `WithDataScope`), which knows who is an administrator or holds
  full data access. Inside the finding package every filter-driven path
  goes through one helper (`visibleFilter`: `visibleTo`, `ListFindingIDs`).
  Three older paths still set the field themselves with the caller's admin
  and full-data decision — the findings list/search, the asset list and
  `/findings/stats`; their SQL gives the same answer as a resolved scope (no
  scope row, nothing).
- **Asset findings list** (`GET /assets/{id}/findings`) goes through the
  same `visibleFilter` as the findings list: scope plus the pentest-membership
  rule, so a pentest finding (PoC in its metadata) reaches campaign members
  only (21b H5).

- **Asset-less exposures are full-data only for writes too** (D11, research
  21b H1): exposure create, ingest and bulk ingest refuse an exposure with no
  `asset_id` from a restricted caller (400), so the fingerprint upsert cannot
  overwrite an asset-less exposure a restricted member cannot see.
- **Indirect lists:** the resolved scope is pushed into SQL as
  `asset_id IN (SELECT asset_id FROM user_accessible_assets WHERE user_id = $u AND tenant_id = $t)`
  (index `(user_id, asset_id)`), built once in `postgres.dataScopeCond`.
- **Only an active principal has scope** (member lifecycle, RFC-050,
  migration 001015). `user_accessible_assets` holds rows only for an ACTIVE
  membership of an ACTIVE account: every refresh function is gated by
  `principal_is_active(tenant, user)`, a disable drops the rows in its
  transaction and a re-enable recomputes them (`refresh_access_for_user`)
  from the frozen groups and grants. `HasFullDataRole` is false for an
  inactive member, and `datascope.MembershipAdminLookup` answers
  `ErrInactivePrincipal` for a disabled or offboarded member, so a background
  job acting for them (scheduled scan, report) refuses instead of running
  with a bypass the person no longer holds.
- **The scope follows its sources in the same transaction** (migration
  001016, RFC-050 W6). Database triggers keep `user_accessible_assets` in
  step whatever code path writes: a group asset row inserted or deleted
  (`asset_owners_scope_sync`), a member leaving a group
  (`group_members_scope_sync`), a group deactivated or re-activated
  (`groups_active_scope_sync`, recomputes every member), a group deleted (its
  asset rows go first, `groups_delete_scope_sync`), a scope rule deleted or
  deactivated (its auto-assigned rows go, instead of `ON DELETE SET NULL`
  orphaning them). A user keeps an asset another active group or a direct
  grant still gives. Narrowing a rule reconciles the whole group (stale
  auto-assignments removed), and an asset-group change reconciles the rules
  of that tenant (it used to look them up with a zero tenant id). Before,
  deactivating a group never removed the access it granted (21b H6/L-12).

### Member lifecycle (disable, offboard, erase)

A person is never hard-deleted (RFC-050 §2). Every membership gate is a
positive check (`Membership.IsActive()`), never `!IsSuspended()`, and
`users.status` must be `active` on every authenticated request.

| Action | Access | Held sources | Owned work |
|---|---|---|---|
| Disable (`/suspend`, SCIM `active=false`) | cut at once: sessions, refresh tokens, sockets, keys `suspended`, scope rows dropped | frozen (groups, grants, ownership kept) | scan schedules `paused`, report schedules and workflows deactivated, administrators notified |
| Re-enable (`/reactivate`) | restored: keys re-activated, scope recomputed | unchanged | stays paused until an administrator resumes it |
| Offboard (`/offboard`, `DELETE`, SCIM delete) | gone: keys `revoked` | stripped: groups, grants, engagement memberships, roles, invitations; membership kept as an `offboarded` tombstone | reassigned (mandatory) to another active member of the tenant; open findings may go back to the queue |
| Erase (`/erase`, owner) | — | — | — ; name and email anonymised, rows and foreign keys kept |

SCIM delete offboards when the member owns nothing to reassign; otherwise it
disables and asks administrators to finish. A re-invite, admin add, SCIM
provisioning or SSO JIT re-activates a tombstone from zero (only the new
role). Tombstones yield no token, no tenant-switcher entry, are left out of
the default member list (`?status=offboarded|all` shows them) and out of SCIM.

### Coverage

| Surface | Before (audit 2026-10, F4) | Now |
|---|---|---|
| `GET /assets`, `/findings` (list, search), `/findings/stats` | scoped | scoped (unchanged) |
| `GET /findings/groups` (every `group_by`: asset, CVE, rule, owner, component, severity, source, type; incl. the total-groups count and the `statuses=fix_applied` Pending Review queue) | **bypass (group names + counts tenant-wide; listed as scoped by mistake)** | scoped: groups and their counts come only from in-scope findings; pentest findings only to campaign members (the view lists no pentest findings at all) |
| `GET /findings/related-cves/{cve}` | **bypass (CVE ids/titles/counts)** | scoped (both the source CVE's components and the related findings) |
| `GET /assets/{id}`, `/findings/{id}`, `/findings/{id}/activities`, `POST /findings/{id}/comments` | scoped | scoped (guard + service) |
| `GET /assets/{id}/full`, `/assets/{id}/findings`, `/assets/{id}/{owners,relationships,components,services,identifiers,state-history,sla-policy}` | **bypass** | 404 (guard) |
| `GET /findings/{id}/{comments,priority-explanation,dataflows,approvals,evidence,ai-triage}` | **bypass** | 404 (guard) |
| `PATCH /findings/{id}/{status,severity,triage,classify,remediation}`, `PUT /tags`, `POST /{assign,unassign,verify,...}`, `DELETE /findings/{id}` | **bypass (write)** | 404 (guard) + service check (`getFindingWithTenantCheck`, status, delete) |
| `PUT/DELETE /findings/{id}/comments/{comment_id}` | bypass | 404 (guard) + comment's finding checked |
| `POST /comments/{comment_id}/reactions`, `DELETE /comments/{comment_id}/reactions/{emoji}` | (new) | comment resolved by (tenant, id); its finding goes through the comment-list gate (data scope, pentest campaign membership): 404. Removing another member's reaction (`?user_id=`) needs owner/admin and is audited |
| `PUT/DELETE /assets/{id}`, activate/deactivate/archive, crown-jewel, snooze, sync, scan | **bypass (write)** | 404 (guard) |
| `POST /findings/bulk/status`, `/bulk/assign` | **bypass (write)** | out-of-scope ids skipped, reported as not found |
| `POST /findings/actions/verify`, `/reject-fix` (by ids), `/fix-applied` (filter) | partly | scoped |
| `POST /findings/actions/verify`, `/reject-fix` (by `filter`, Pending Review) | **bypass (write: the scope field was set but the filter builder ignored it)** | scoped; admins unchanged |
| `GET /findings/remediation-groups`, MCP `list_remediation_groups` | **bypass (fix titles, keys, counts tenant-wide)** | groups and counts from in-scope findings only |
| `POST /findings/remediation-groups/{key}/resolve` | partly (out-of-scope members not changed, but counted against the abuse guard and reported as `failed`) | only in-scope findings are counted, changed and reported |
| `POST /findings/actions/assign-to-owners` | **bypass (write)**: fail-open for members without a group even under policy `nothing`; pentest findings of other campaigns assigned; admins with a scope row restricted | enforcer scope + pentest rule; admins unrestricted |
| `GET /findings/stats` under policy `nothing` when the scope lookup fails | fell through to tenant-wide counts | error (fail closed) |
| `POST /findings/bulk/status` on a pentest finding | **bypass (write)**: changed it, for any holder of `findings:bulk_update` whose scope covers the asset, campaign member or not (the single-finding path refuses) | refused like the single-finding path (`failed`, "managed via the pentest module"); other ids in the call unaffected |
| `POST /remediation/campaigns/{id}/resolve` (filter campaign) | ids counted tenant-wide against the abuse guard and its 2000 cap, then out-of-scope ones skipped by the bulk path; a campaign filtered to pentest findings changed them | ids taken from the caller's scope and pentest rule (`ListFindingIDs`), pentest findings refused by the bulk path; the keyed (solution-family) path goes through the remediation-group resolve above |
| `POST /assets/bulk/status`, `/assets/bulk/sync` | bypass | out-of-scope ids skipped |
| `POST /approvals/{id}/{approve,reject,cancel}`; `GET /approvals` | bypass | 404 / list filtered per page |
| `POST /findings/ai-triage/bulk`; `GET /findings/{id}/ai-triage/{triageId}` | bypass | out-of-scope ids reported as not found; a result is checked against its own finding |
| `GET /exposures`, `/exposures/{id}`, `/{id}/history`, state changes, ctem-id, delete | **bypass** | list filtered; by-id 404. An exposure with no asset is hidden from restricted members |
| `GET /asset-groups/{id}/assets`, `/{id}/findings` | **bypass** | filtered |
| `GET /attack-surface/attack-paths` | **bypass** | `top_assets` filtered |
| `GET /attack-surface/exposure-chains`, MCP `get_exposure_chains` | **bypass** | a chain is returned only when every hop is in scope |
| `GET /attack-surface/stats` | bypass | asset counts, exposed-services list and recent changes scoped |
| `GET /dashboard/stats` recent activity | **bypass (finding titles)** | filtered |
| `GET /dashboard/executive-summary` (+ export) `top_risks` | bypass | filtered |
| `GET /dashboard/stats/global` recent activity | bypass | per organization: filtered where the caller is restricted there |
| `GET /vulnerabilities/{id}/affected-assets`, `/cve/{cve}/affected-assets` | bypass | filtered |
| In-app notifications (`GET /notifications`, unread count, live push) for finding / asset events | **bypass (audience all, body = finding message)** | a finding/asset notice is listed, counted and pushed only to users whose scope covers its asset |
| WebSocket `finding:{id}`, `triage:{id}` | **bypass** (permission only) | also requires the finding to be in scope |
| `GET /notification-outbox` (+ `/stats`, `/{id}`, retry, delete), `GET /integrations/{id}/notification-events` | **bypass (every finding/asset event, owner emails) to members and viewers via `notifications:read` / `integrations:read`** | channel managers only: `integrations:manage` in addition (owner/admin by default); not scoped, because a channel manager already routes the whole stream (L-03) |
| `POST /assets/import/nessus-findings` | **bypass (write)**: ran as a trusted server-side sensor, so a member added findings to any host and auto-resolved any tool's findings on it (`?tool=`) | runs with the uploader's rights (`ingest.Options.Actor`): a restricted uploader only adds findings to existing in-scope assets, creates no asset, never auto-resolves; hidden and unknown hosts both count as `assets_skipped_out_of_scope`. An unrestricted uploader auto-resolves only with the default `tenable` tool (any other `?tool=` = partial coverage). Audited `asset.imported` (L-05) |
| `GET /components/{id}/assets` (reverse lookup), `GET /components` (incl. `?asset_id=`, export), `POST/PUT/DELETE /components[/{id}]`, `POST /components/import?asset_id=`, `GET /vulnerabilities/...` dependency detail | **bypass**: names, criticality and risk of every asset using a package; writes on any asset of the tenant | the reverse lookup and list only show in-scope assets (`dataScopeCond` in SQL); an out-of-scope asset id or dependency id answers 404 (`ComponentService`, `SBOMImportService`; L-10) |
| `/repositories/{id}/branches/**` (list, get, default, compare, create, update, delete) | **bypass** (tenant only) | the repository must be in scope (`AssetService.GetAssetInCallerScope`): 404 otherwise (L-10) |
| `GET /threat-models` (+ `/{id}`, `/{id}/coverage`), `POST /threat-models/generate` | **bypass** (crown-jewel model names, threat paths through any asset) | crown-jewel models of out-of-scope assets are hidden (404 by id, also on generate, which names the asset); a threat is listed and counted in coverage only when its entry point, target, hop and evidence finding are all in scope. Model rollup counters stay graph-wide (L-10) |
| `GET/POST/DELETE /business-services/{id}/assets`, `POST/DELETE /business-units/{id}/assets` | **bypass** (names; links change an asset's effective criticality) | the list shows in-scope (and not deleted) assets; linking or unlinking an out-of-scope asset answers 404 (L-10) |
| `GET /ctem-cycles/{id}/scope` | bypass (asset names of the snapshot) | in-scope assets of the snapshot only (L-10) |
| `/credentials/**` (list, identities, identity exposures, related, stats, get, reveal, resolve, accept, false-positive, reactivate) | **bypass**: every leak of the tenant, incl. reveal and state changes, while `/exposures/{id}` hid the same row | leaks on in-scope assets only (`dataScopeCond`); an asset-less leak is in nobody's asset scope (unrestricted callers only); by id: 404. Stats count only those (and only credentials) (L-10) |
| `GET /vulnerabilities/active`, `/active/stats`, MCP `list_active_cves` | bypass (CVE ids, affected counts) | aggregated only over findings on in-scope assets (L-10) |
| `GET /groups/{g}/assets` (`groups:read`, a member default) | **bypass** (any team's asset names) | only the group's assets in the caller's scope are listed and counted (L-10) |

### Dashboards follow the viewer

Owner decision D6 (research doc 15 P1-4): a dashboard number means "in what
you can see". `GET /dashboard/stats` counts (assets and findings by type,
status, severity, averages, repositories, the monthly finding trend) are
computed with the same SQL condition as every scoped list:

| Viewer | Counts |
|---|---|
| Owner / admin / full-data role / unrestricted member | the organization |
| Restricted member | only their in-scope assets and those assets' findings (0 in a fail-closed organization without a group) |
| Restricted member with **`dashboard:aggregate`** (new permission, migration `000774`; owner and admin by default, custom roles when granted) | the organization totals; breakdown buckets under 5 are left out (k-floor), so a total does not single out an asset they cannot see |

Recent activity and top risks are row data and stay limited to the viewer's
scope whatever the permission. MTTR (`GET /dashboard/mttr` and
`/dashboard/mttr-analytics`) follows the viewer the same way (research 24
§5.1): a restricted member averages their own in-scope findings, with
`dashboard:aggregate` the organization. The other dashboard metrics
(velocity, data quality, risk trend, program, process and executive metrics)
move the same way in a follow-up; until then they stay in the table below.

Remediation campaign progress follows the reader too (research 15 L-18,
research 24): a restricted member reading a campaign (`GET`, list, and the
responses of update, status and refresh) sees the finding and resolved counts
of their own in-scope findings. The stored counts stay organization-wide,
because auto-complete reads them; a restricted read never persists its view.
### Scheduled report recipients

A scheduled report mails organization posture out, so its recipients are
limited (owner decision D12, research doc 15 L-19): an **active member of the
organization**, or an address in one of its **`Security.AllowedDomains`**
(exact domain, case-insensitive; no allowed domains means members only).

- `POST /reports/schedules` refuses (400) any other recipient; activating a
  schedule (`PATCH /reports/schedules/{id}/toggle`) re-checks, so a schedule
  written before the rule, or whose recipient has left, is not switched back
  on with them.
- The scheduler re-checks every recipient at send time and skips the ones no
  longer allowed (logged); with nobody left it sends nothing (`no_recipients`).
- Create, activate and delete are audited (`report_schedule.*`, with the
  recipients on create).
- The report body is still tenant-wide; rendering under the creator's scope is
  part of P1-4 (D6).
### Scheduled reports render under their creator's scope

Owner decision D6 (research doc 15 P1-4): a scheduled report shows what its
creator can see, decided at each run (`datascope.Enforcer.ForUser`, the same
admin and full-data rules as a request). A restricted creator's report
counts only their in-scope assets and findings (none without a scope row; the
trend window takes the same scope). A schedule with no recorded creator, or whose creator can no
longer be resolved (left the organization), is not rendered or sent
(`failed`).

### Deliberately tenant-wide (counts only, no row data)

These return aggregates over the whole tenant to every holder of the read
permission. Filtering them would need a scoped variant of each aggregate
query; none exposes a row, name, title or id of an out-of-scope object.

| Endpoint | Why tenant-wide |
|---|---|
| `GET /dashboard/{velocity,data-quality,risk-trend,process-metrics,program-metrics}`, executive-summary metrics | program-level KPIs, counts and averages |
| `GET /attack-surface/stats` average risk score and per-type breakdown | aggregate; the counts and row lists on that endpoint are scoped |
| `summary` blocks of attack paths / exposure chains | graph-wide counts (reachability needs the whole graph) |
| `GET /assets/stats`, `/assets/facets`, `/assets/tags` | aggregate counts / tag vocabulary |
| `GET /exposures/stats` | counts by state/severity, MTTR |
| `GET /findings/analytics/sources` | counts per tool |
| `GET /approvals` `total` | the page is filtered; the total is the tenant's pending count |

**Not covered by data scope** (separate access models): pentest findings and
attachments (campaign membership), remediation campaigns,
scans, audit logs, report schedules, and access-control administration
(`/groups/{id}/assets/{assetId}`, which defines scope and needs `groups:write`).
The reachability oracle used by priority classification and threat models reads
the full graph on purpose (`GetExposureChains` stays unscoped).

**Asset references a caller writes** go through `datascope.Enforcer.AssertAssetRef`:
the asset must be a live asset of the tenant (checked for unrestricted callers
too) **and** in the caller's scope; a foreign, unknown, deleted or out-of-scope
id all answer 404. It fails closed when not wired (research doc 15, L-02;
research doc 21b, C1/C3/C4). Used by:

- `POST /pentest/campaigns/{id}/findings` (`asset_id`);
- `POST /findings` (`asset_id`; a `branch_id` must also be a branch of that
  asset, which pins it to the tenant);
- `POST /exposures` and `POST /exposures/ingest` (`asset_id`; the bulk ingest
  uses the batch form `FilterAssetRefs` and drops refused items with the one
  reason `asset not found`);
- `POST /pipelines/{id}/runs` (`asset_id`, which is copied into every step
  command; a workflow trigger with no user gets the tenant check).

**Database backstop** (migrations 000920-000922): every column that references
`assets(id)` from a table with a `tenant_id` also has a composite foreign key
`(tenant_id, <asset column>) → assets(tenant_id, id)`, so a cross-tenant
reference is refused by the database whatever code writes it, including
internal writers (ingest, EASM, CT monitor). A new table that references
assets must add one; `TestAssetRefTenantFKs_Schema` fails otherwise. Tables
without a `tenant_id` (`asset_owners`, which has its own same-tenant trigger,
`asset_repositories`, `asset_group_members`, `asset_sources`,
`attack_path_nodes`, `compensating_control_assets`) are not covered; their
writers join the asset in the caller's tenant.

Pre-delete counts are tenant-scoped: `DELETE /assets/{id}` counts only the
tenant's own findings, so a row another tenant pointed at the asset neither
blocks the delete nor has its count disclosed.

Outside a request (WebSocket subscriptions, cross-organization dashboard) admin
status is the team role from `v_user_effective_role` (owner/admin) — the same
source as the access token's `admin` claim; the live-push recipient query reads
the same view in SQL. Keep them in step if that derivation changes.

## Module-Gate Layer (per-tenant feature gating)

Above the permission and role checks there is a third, orthogonal layer: the
**module gate**. `middleware.ModuleGate.RequireModule(moduleID)`
(`internal/infra/http/middleware/module_gate.go`) wraps a route group and returns
`403 MODULE_NOT_ENABLED` when the tenant has explicitly disabled that product
module. It is wired onto **26 route groups** in
`internal/infra/http/routes/routes.go` — e.g. `attack_surface`, `exposures`,
`suppressions`, `remediation`, `compliance`, `pentest`, `threat_intel`,
`reports`, `ctem_cycles`, `attacker_profiles`, `business_services`,
`compensating_controls`, `priority_rules`, `scope_config`, `components`,
`relationships`, `credentials`, `workflows`, `integrations`, `scan_pipelines`,
`scanner_templates`, `template_sources`, `attack_simulation`, `control_testing`,
`branches`, `iocs`.

**This is a feature gate, not a security boundary, and it is deliberately
fail-open.** A nil gate, missing provider, empty tenant, a core module, or any
lookup miss all resolve to "enabled" — only an explicitly-disabled non-core
module returns 403. Disabled sets are cached per tenant with a short TTL (60s
default) and invalidated on toggle. Permission and tenant-isolation checks are
the real access-control boundary; the gate only hides modules a tenant has
turned off. Core modules (see `module.IsCoreModule`) can never be gated off.

## Middleware Reference

### Permission Middleware

```go
// Single permission required
middleware.Require(permission.AssetsRead)

// Any of the permissions (OR)
middleware.RequireAny(permission.AssetsRead, permission.FindingsRead)

// All permissions required (AND)
middleware.RequireAll(permission.AssetsWrite, permission.FindingsWrite)
```

### Role Middleware (Team Context)

```go
// Specific roles required (from database membership)
middleware.RequireTeamRole(tenant.RoleOwner, tenant.RoleAdmin)

// Minimum role level (uses hierarchy)
middleware.RequireMinTeamRole(tenant.RoleAdmin)  // admin or owner

// Shortcuts
middleware.RequireTeamAdmin()   // owner or admin
middleware.RequireTeamOwner()   // owner only
middleware.RequireTeamWrite()   // owner, admin, or member
```

### Tenant Middleware

```go
// JWT-based tenant (from token claims)
middleware.RequireTenant()

// URL-based tenant (from path parameter)
middleware.TenantContext(tenantRepo)
middleware.RequireMembership(tenantRepo)
```

## Implementation Pattern

### Permission-based Routes (Recommended)

```go
router.Group("/api/v1/assets", func(r Router) {
    // Read operations
    r.GET("/", h.List, middleware.Require(permission.AssetsRead))
    r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))

    // Write operations
    r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
    r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))

    // Delete operations
    r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetsDelete))
}, authMiddleware, userSyncMiddleware, middleware.RequireTenant())
```

### Role-based Routes (Team Management)

```go
router.Group("/api/v1/tenants/{tenant}", func(r Router) {
    // Read operations - any member
    r.GET("/members", h.ListMembers)

    // Admin operations
    r.PATCH("/", h.Update, middleware.RequireTeamAdmin())
    r.POST("/members", h.AddMember, middleware.RequireTeamAdmin())

    // Owner-only operations
    r.DELETE("/", h.Delete, middleware.RequireTeamOwner())
}, authMiddleware, userSyncMiddleware, tenantContext, requireMembership)
```

## Role Hierarchy

```
owner (4) ─┬─ Can do everything
           │
admin (3) ─┼─ Can manage team members and settings
           │
member (2) ┼─ Can create/edit resources
           │
viewer (1) ┴─ Can only view resources
```

## Security Considerations

1. **Tenant Isolation**: Access tokens are scoped to a specific tenant. Users must exchange their refresh token for a tenant-scoped access token.

2. **Permission Validation**: The access token carries the user's full permission
   array, so the hot path checks permissions in-token with no per-request DB read.
   To close the stale-token window, a per-user **permission version** (Redis `INCR`)
   is bumped on any grant/revoke — every `RoleService` role-set change and the
   member-role update (`PATCH /tenants/{t}/members/{id}`). On every token-tenant
   request `EnrichPermissions` resolves the effective permission set from
   Redis/DB, and:
   - `HasPermission` then answers **only from that fresh set**; the token's
     embedded array is never consulted again on that request, so a revoked
     permission stops working on the next request, **reads included**;
   - when the token's version is confirmed **stale**, a **write** is rejected
     with `409 permissions_stale`; a **read** proceeds only after the token's
     `admin` flag and `role` are **re-derived from the database** (the team role,
     read from `tenant_members`/`user_roles` without the membership cache), so a
     demoted admin loses the admin bypass on the next request. If the team role
     or the permission set cannot be read for a stale token, the read gets the
     same `409` (fail closed);
   - when the token is **not** stale and the permission lookup fails
     (Redis/DB outage), the token's own permissions are used: they are current,
     and an outage is not a revocation.

   Role-set changes also drop the user's cached membership, so
   `RequireTeamAdmin/Owner` see the new team role on the next request.
   `RevokeAllSessions` forces immediate re-auth. So the token is the fast path,
   but the database is the source of truth — see
   [permission-realtime-sync.md](./permission-realtime-sync.md).

3. **IDOR Prevention**: JWT-based tenant routes eliminate IDOR by design - users can only access their current tenant's data.

4. **Team Management Security**: Team operations use database-based membership verification via `RequireMembership` middleware.

5. **Owner Protection**: Team owners cannot be demoted or removed. Only team deletion removes the owner.

6. **Invitation Security**: Invitations are validated against the accepting user's email address.

## API Routes Summary

```
Public (No Auth):
├── GET  /health
├── GET  /ready
├── GET  /metrics
└── POST /api/v1/auth/*

User Profile (JWT Required):
└── /api/v1/users/me/*

JWT-Tenant Routes (Permission-based):
├── /api/v1/assets/*           → assets:read/write/delete
├── /api/v1/components/*       → components:read/write/delete
├── /api/v1/findings/*         → findings:read/write/delete
├── /api/v1/vulnerabilities/*  → vulnerabilities:read/write/delete
└── /api/v1/dashboard/*        → dashboard:read

URL-Tenant Routes (Role-based):
├── /api/v1/tenants                      → Any authenticated
├── /api/v1/tenants/{tenant}/members     → viewer+ (R), admin+ (W)
├── /api/v1/tenants/{tenant}/invitations → viewer+ (R), admin+ (W)
└── /api/v1/tenants/{tenant}             → admin+ (U), owner (D)

Invitations:
└── /api/v1/invitations/{lookup,decline,accept,accept-with-refresh}
                                         → token in the body; accept needs the invited email
```

Legend: (R) = Read, (W) = Write, (U) = Update, (D) = Delete

## Settled model — the rules we lock going forward

The authorization model was reviewed end-to-end (2026-09, `docs/authz-audit.md`)
and standardized. The following are **decisions**, not accidents — each was made
deliberately and, where a design choice was involved, benchmarked against
Tenable.sc's RBAC.

1. **Allow-only, default-deny, roles only.** A user's effective permissions are
   the *union* of what their roles grant, and roles are the **only** source of
   permissions. There is no deny-override. This mirrors Tenable.sc, which is
   purely additive with no deny-override.

   Groups (teams) carry **only data scope** (which assets their members see),
   never permissions. Group permission sets and per-group permission overrides
   were removed: they were never read by enforcement, yet the UI said members
   inherit them. The `/api/v1/permission-sets` and
   `/api/v1/groups/{id}/permission-sets` routes are gone, no code reads or
   writes their tables, and `team:permission_sets:*` left the catalog
   (migration 000670 archives those catalog rows and role grants in
   `access_control_removed_archive`). The tables themselves are dropped by a
   later contract migration, after a release (expand-contract).
   `GET /api/v1/me/permissions` now returns the caller's role-derived
   permissions (it used to return the group-derived set).

2. **Backend is the only authority.** The frontend hides controls the user lacks
   perms for as a UX nicety; it is never the boundary. Every mutation is
   independently gated server-side. UI perm checks that duplicate a server gate are
   convenience, not security.

3. **Effective permissions come from the database, not blindly from the token.**
   The token is the fast path; the per-user permission version + `EnrichPermissions`
   re-resolution + `409` on stale writes make the DB the source of truth (see
   Security Consideration #2 and `permission-realtime-sync.md`).

4. **Granular over coarse.** Action routes are gated on the most precise permission
   that describes the action (e.g. `findings:status`, not `findings:write`), so the
   role matrix tells the truth about who can do what. Tightening a role's grant is a
   *product* decision made via seed/migration, never by silently widening a route's
   gate.

5. **No time-limited grants.** There is no `expires_at` on role assignments.
   Tenable.sc has no expiring grants either; revocation is immediate via
   `RevokeAllSessions` + version bump. → we will **not** build expiring grants (YAGNI).

6. **The module gate is a feature flag, not a security boundary.** It is fail-open
   by design (see "Module-Gate Layer"). Never rely on it to protect data — that is
   the job of the permission gate + tenant isolation.

7. **`user_roles` is the RBAC role set; the team role comes from the system role IDs only.**
   Permissions are resolved only from `user_roles`, which holds exactly the roles
   an administrator granted (custom roles, several roles, or none).
   The **team role** (owner/admin/member/viewer) is what the token's `role` claim
   and `admin` flag, `IsOwner`/`RequireOwner`/`RequireAdmin`, and
   `RequireTeamAdmin/Owner` all read. It is computed by the view
   `v_user_effective_role` (migration `000245`), one row per membership:
   - the highest of the four **system roles** the user holds, matched by role
     id (`…0001` owner > `…0002` admin > `…0003` member > `…0004` viewer);
   - a user holding no system role gets the membership label
     (`tenant_members.role`, derived by `MembershipRoleForRoleIDs`), **capped at
     `member`**: an `owner`/`admin` label without the matching system role
     resolves to `viewer`. Removing every role from an administrator therefore
     removes their admin powers.
   - **Custom roles never count**, whatever their slug or `hierarchy_level`.
     Before `000245` the view took the slug of the highest-`hierarchy_level`
     role, so a custom role with slug `owner` and level 100 made its holder
     owner (audit F1). Custom roles may no longer use a system slug
     (`owner`/`admin`/`member`/`viewer`) or a level at or above admin's 80
     (service validation + `CHECK` constraints `roles_custom_slug_not_reserved`
     and `roles_custom_level_below_admin`); the migration renamed offending
     roles to `custom-<slug>` and clamped levels to 79. `hierarchy_level` is
     display order only.
   - The token's `role` claim is this team role; RBAC role slugs are never put
     in its place.

   Nothing may re-derive the role set from the label: the `role-sync` controller
   only restores the owner role of a tenant owner who lacks it, and reports (does
   not repair) active members with no role. It used to re-grant the label's
   system role hourly, which brought back roles administrators had removed.

8. **Role grants are bounded by the granter's own grants** (`accesscontrol/grant_guard.go`).
   Every path that changes a role set (assign, set, bulk assign, remove,
   invitation/created-user grants) or what a custom role carries (create,
   update) is checked in `RoleService` against the actor's roles in the
   database: only an owner may grant the owner role; anyone else may grant only
   roles whose permissions (and full data access) they hold, so nobody can raise
   their own privileges; **removal has the same ceiling** (`RemoveRole`, and every
   role `SetUserRoles` drops): nobody may take away a role they could not have
   granted, so a delegated role manager cannot strip admin from an administrator;
   only an owner may change an owner's roles, and the tenant's owner keeps the
   owner role. **Deleting a custom role has the same ceiling** (`DeleteRole`,
   owner decision 2026-10-02): `DELETE /api/v1/roles/{id}` needs
   `team:roles:delete` *and* every permission (and full data access) the role
   carries, so an administrator cannot delete an owner-built role holding
   owner-only permissions (403); owners may delete any custom role. The handler-level check
   (`assertCanGrantPermissions`) lets administrators through, so the service is
   the enforcement point. SCIM mappings, SSO/SAML JIT and the membership-role
   update can never produce `owner`.

9. **Owner/admin-only surfaces (owner decision 2026-10-02).** Sensor writes
   and keys, the audit log, billing, and other users' API keys are owner/admin
   only; peer administrators, audit-chain rebaseline and SCIM token mint/revoke
   are owner only; the platform administrator only bootstraps an
   organization's first owner. Members and viewers keep the member list and
   `sensors:read`. **Member emails are owner/admin only** (owner decision
   2026-10-02, superseding the earlier "emails stay visible"): the member list
   (`GET /api/v1/tenants/{tenant}/members?include=user`) omits `email` and
   `last_login_at` for anyone else and its `search` matches names only, so a
   search cannot confirm an address; ids, names and avatars stay for the
   assignee and owner pickers. Business-unit delete is owner/admin only.
   Role diff (migration `000246`):

   | Role | Removed |
   |------|---------|
   | member | `sensors:write`, `audit:read`, `settings:billing:read` |
   | viewer | `audit:read`, `settings:billing:read` |

10. **Custom templates are trusted code (owner decision 2026-10-02).** A
    custom scanner template (nuclei especially) decides which hosts the sensor
    contacts and what it sends, so only owners and administrators author one:
    `scans:templates:write` (scanner templates) and `scans:sources:write`
    (template sources, which pull templates from a URL) are owner/admin only;
    migration `000262` removed both from member. Members and viewers keep
    `scans:templates:read` / `scans:sources:read` and pick approved templates
    for a scan by id (`scanner_config.custom_template_ids`). `POST
    /api/v1/commands` refuses a payload that embeds `custom_templates`
    unless the caller is an owner or administrator (403), even though members
    hold `commands:write`. Templates are still validated as above. The
    sensor-side half (custom-template traffic through the RFC-034
    scope-enforcing forwarder) is an RFC-034 follow-up.

    | Role | Removed |
    |------|---------|
    | member | `scans:templates:write`, `scans:sources:write` |

11. **Scan commands are owner/admin only and scoped (RFC-040 Q5 (c), owner
    decision 2026-10-03).** `POST /api/v1/commands` with `type: "scan"`
    makes a sensor scan whatever the payload names, so it is refused (403)
    for anyone but owners and administrators, although members keep
    `commands:write` for the other command types. For an administrator the
    payload's `target`/`targets` go through the checks of a scan trigger
    (`scan.Service.GateCommandPayload`): the target validator with the
    private-range policy (internal addresses only inside a scan zone), active
    scope exclusions (a failed lookup refuses, fail closed), and zone routing
    (all targets in one zone, nothing uncovered, a pinned sensor assigned to
    that zone; the command is stamped with the zone). Any refused target
    refuses the whole command (400) instead of being dropped, targets nested
    in `config`, `scanner_config`, `context` or `step_config` are refused,
    and the stored payload carries the checked list. Every attempt is
    audited as `command.created`: `success` with sensor, zone and targets, or
    `denied` with the reason. Without the gate wired, scan commands answer
    500 (fail closed).

### Known, deliberate gaps (do not "fix" without a decision)

- **Two admin oracles.** Permission-based `IsAdmin` (from the token) and live-DB
  team-role (`RequireTeamAdmin/Owner`) are separate mechanisms. They read the
  same team role, and a role change makes the token stale, after which
  `EnrichPermissions` re-derives `IsAdmin`/`role` from the database (see Security
  Consideration #2), so they no longer disagree after a demotion on the
  token-tenant chains. Unifying them onto live membership on every request
  (which would also fix `IsOwner` under OIDC) is a phased refactor —
  **deferred** because a missing membership middleware on any chain would 403 a
  whole route group.
- **Members without a scope row see nothing, in every organization.** The
  2026-10-02 per-organization choice (`everything` for existing
  organizations) was retired with the owner's signoff on 2026-10-04 (decision
  D2, see *Data scope* above). Do not add a fail-open mode back.
- **RLS is shadow-mode.** ~99 policies exist, 0 tables have RLS enabled. This is
  intentional (staged rollout), not a dead control. Tenant isolation is enforced by
  convention (`WHERE tenant_id = $n`) today; do not assume RLS backstops it.

## Granular permissions enforced (D-4, migrations 000771/000772)

Thirty permissions were defined, seeded and shown in the role editor, yet no
route checked them. Each is now either enforced or removed.

**Enforced on top of the route's existing gate** (`RequireAll(old, new)`, so no
role gains anything). Migration 000771 grants the new permission to every role,
system or custom, that held the old gate, recording each grant in
`granular_permission_backfill` (its down removes exactly those), so every
role keeps its abilities. An administrator can now remove the new permission
from a custom role to deny that one action.

| Permission | Routes | Old gate |
|---|---|---|
| `assets:import` | `POST /assets/import/{csv,nessus,nessus-findings,kubernetes}` | `assets:write` |
| `scans:execute` | `POST /scans/{id}/trigger`, `POST /scans/quick`, `POST /assets/{id}/scan` | `scans:write` / `assets:write` |
| `integrations:pipelines:execute` | `POST /pipelines/{id}/runs` | `integrations:pipelines:write` |
| `ai_triage:read` | `GET /findings/{id}/ai-triage*`, `GET /findings/ai-triage/config` | `findings:read` |
| `ai_triage:trigger` | `POST /findings/{id}/ai-triage`, `POST /findings/ai-triage/bulk` | `findings:write` |
| `findings:exposures:read` | `GET /exposures`, `/{id}`, `/stats`, `/{id}/history` | `findings:read` |
| `findings:exposures:write` | `POST /exposures`, `/ingest`, `PUT /{id}/ctem-id` | `findings:write` |
| `findings:exposures:triage` | `POST /exposures/{id}/resolve`, `/reactivate` (with `findings:write`), `/accept`, `/false-positive` (with `findings:approve`) | as listed |
| `findings:exposures:delete` | `DELETE /exposures/{id}` | `findings:delete` |
| `integrations:scm:read` | `GET /integrations/scm` | `integrations:read` |
| `integrations:scm:write` / `:delete` | create/update / delete of an SCM-category integration (checked in the handler) | `integrations:manage` |
| `team:groups:assets` | `POST/PUT/DELETE /groups/{id}/assets*` | `team:groups:write` |
| `team:read` | `GET /tenants/{tenant}` | membership |
| `team:members:read` | `GET /tenants/{tenant}/members`, `/members/stats`, `/invitations` | membership |
| `settings:read` | `GET /tenants/{tenant}/settings`, admin `GET .../settings/*` | membership / team admin |
| `team:update` | `PATCH /tenants/{tenant}` | team admin |
| `team:members:write` | member add/role/suspend/reactivate/remove, admin-created users and setup links | team admin |
| `team:members:invite` | create/resend/delete invitations | team admin |
| `settings:write` | every `PATCH/PUT/POST .../settings/*` (owner-only ones stay owner-only) | team admin / owner |
| `team:delete` | `DELETE /tenants/{tenant}` | team owner |

`/tenants/{tenant}/...` routes name the tenant in the path, which may differ
from the credential's tenant, so they use `RequireTenantPermission`: the
caller's permissions are resolved **in the path tenant** (owner passes); a
permission held in another tenant never counts. Every member could read the
organization, its members and its settings, so 000771 also grants
`team:read`, `team:members:read` and `settings:read` to every existing custom
role. A custom role created later needs them explicitly for those reads.

`findings:export` gates the server-side findings export (RFC-048, #1058); `assets:export` is kept for the planned asset export of the same RFC and is not removed.

**Removed** (000772; catalog rows and grants archived in
`access_control_removed_archive`, restored by its down):

| Permission | Why it is meaningless |
|---|---|
| `compliance:frameworks:write` | Frameworks are a read-only seeded catalog; no API writes them. |
| `compliance:reports:read` | No compliance report API; the page is a redirect. |
| `findings:policies:*` | The policies module was retired (000215) without ever having routes. |
| `settings:billing:read`, `settings:billing:write` | No billing API or page. |

## CI invariants that keep this from drifting

These tests fail the build if the model erodes. Treat them as executable spec:

| Invariant | Test | What it guarantees |
|-----------|------|--------------------|
| **Every route is gated or explicitly allowlisted** | `tests/unit/route_authz_coverage_test.go` (AUTHZ-02) | A go/ast walk of `routes/*.go` resolves chi `.Group` nesting + inherited gates; any route with no `Require*`/`RequireTeam*`/`RequireRole` and not in `allowlistPrefixes` fails the build, naming the route. Removing one `Require(...)` → red. |
| **Go permission registry ≡ DB seed** | `tests/unit/permission_catalog_sync_test.go` (AUTHZ-17) | Parses the seed migrations and asserts set-equality with `permission.AllPermissions()`. A permission added to code but not seeded (or vice-versa) → red. |
| **No tenantless by-id statement on a tenant-scoped table** | `tools/lint/tenantsql` (D-11) | Folds the SQL each `internal/infra/postgres` function sends and fails on `WHERE id = $n` against a table with a `tenant_id` column when the statement has no tenant predicate, unless the method is named `...ForPlatform`/`...Unscoped` (never callable from an HTTP handler) or the shrink-only `allowlist.txt` records why. See `tools/lint/tenantsql/README.md`. |
| **Every referenced permission exists** | `tests/unit/permission_references_exist_test.go` | Every value in `module.ModulePermissionMapping` (sidebar/bootstrap), every `permission.X` constant used in api Go code, and every value of the web `Permission` object (`web/src/lib/permissions/constants.ts`) is in `permission.AllPermissions()`. A reference to a permission no role can hold (which silently hides a module from every non-admin) → red. |

Each module in `ModulePermissionMapping` names the permission its routes gate
on, so the sidebar and the API agree (for example Attack Surface → `assets:read`,
CTEM Cycles → `ctem:cycles:read`, Scan Pipelines → `integrations:pipelines:read`).

## How to … (recipes that stay inside the invariants)

### Add a new permission

1. Add the constant to `pkg/domain/permission/permission.go` **and** include it in
   `AllPermissions()`.
2. Add the same string to the DB seed (a new numbered migration under
   `migrations/` — additive `INSERT ... ON CONFLICT DO NOTHING`, with a matching
   `.down.sql`).
3. Add the string to the UI permission constants so the frontend can gate on it.
4. Map it into the default roles that should hold it (`role_mapping.go` + seed).
5. `go test ./tests/unit/...` — the catalog-sync test proves 1↔2 agree.

### Gate a new route

- Attach the least-privilege permission at registration:
  `r.POST("/", h.Create, middleware.Require(permission.FooWrite))`.
- For team-management routes under `/tenants/{tenant}`, use `RequireTeamAdmin()` /
  `RequireTeamOwner()` (live membership) instead of a permission.
- If the whole route group belongs to a product module, wrap it with
  `ModuleGate.RequireModule(moduleID)` **in addition to** (never instead of) the
  permission gate.
- If the route is legitimately unauthenticated or self-scoped (auth, `/users/me`,
  agent-key, SCIM, webhook, admin-realm, health), add it to `allowlistPrefixes` in
  `route_authz_coverage_test.go` **with a reason comment** — that is the only way to
  pass the coverage gate without a gate, and it forces the decision to be explicit.

### Enforce object-level (row) authorization

Permission gates answer "may this user do this *kind* of thing"; they do **not**
answer "may they touch *this* row". For that:

- Always scope repository reads/writes by `tenant_id` (every mutating query must
  carry `AND tenant_id = $n` — see `ScanRepository.Update`, AUTHZ-10). Do not trust
  an id from the URL to already be tenant-scoped.
- For non-admin data-scope narrowing, use `datascope.Enforcer` (inject it with
  `SetDataScope`): `AssertAsset`/`AssertFinding` for by-id paths (deny =
  `ErrNotFound`), `Filter`/`FilterFindings` for bulk ids, and `Resolve` + an
  SQL predicate from `postgres.dataScopeCond` for lists. New routes under
  `/assets/{id}` or `/findings/{id}` are guarded automatically. Add any new
  asset-bound list to the coverage table in *Data scope*.
- Never authorize a mutation off the request body's tenant/owner fields — derive the
  principal's tenant from the authenticated context (or, for agents, from the agent
  key), never from client-supplied data.

## Web console: mutating controls follow the route table

The web console shows a mutating control (Save, Delete, Add, Test, Sync) only
when the caller passes the gate of the API route it calls. The gates come from
`web/src/config/api-route-permissions.json`, which
`tests/unit/route_permission_map_test.go` generates from the route source
(`UPDATE_ROUTE_PERMISSIONS=1 go test ./tests/unit -run TestRoutePermissionMapIsCurrent`;
CI fails when it is stale). Components call `useCanMutate("METHOD /path")`
(`web/src/lib/permissions/can-mutate.ts`) instead of picking a permission by
hand, which is how about 15 settings controls drifted from the API (shown and
then 403, or hidden although allowed). This is UX only; the API gate stays the
authority.
