# Limits and feature denies

Every organization is **unlimited and may use every feature** unless someone set a limit or a feature deny for that organization:

- the **instance operator** (a platform administrator of this installation),
  in the console;
- a **source** plugged into the entitlement service. A self-hosted install
  has none. A hosted service runs a control plane that writes limits and
  denies through the internal API.

So a self-hosted install with default settings shows nothing limit-like: no
Usage & limits page, no badges, no prompts. An installation that serves
several customers (a hosting provider, a group with subsidiaries) uses the
same limits to cap each organization, in neutral words.

Limits are capacity caps, not a security boundary.

## The one service

`internal/app/entitlement.Service` answers every question about limits and
features. Nothing else checks a limit, a plan, a tier or an edition:
`tests/unit/entitlement_keys_test.go` fails on such a check anywhere in the
API or the web console, and lists every key below.

| Call | Use |
|------|-----|
| `Check(tenant, key, delta)` | refuses an addition over the limit (`*limits.ErrLimitReached`); fail-closed |
| `Headroom(tenant, key)` | how many more may be added, for a batch that admits part of its rows; fail-closed |
| `Effective(tenant)` | limits with usage, denied features, `over_limit`, `applies` |
| `NotEntitled(tenant)` | the modules the organization may not use (module gate, jobs, console) |
| `Allowed(tenant, feature)` | a named feature below module level |
| `CheckOrgsPerUser(user)` | the per-person cap on self-service organizations |
| `ApplyControlPlane(...)` | the control plane's write (internal API) |

### Sources

Limits and denies come from the operator's own rows plus the configured
`limits.Source` implementations:

| Source | Where | Status |
|--------|-------|--------|
| none | every self-hosted install (default) | shipped |
| control plane | rows of origin `control_plane`, written through the internal API of a hosted service | shipped (enabled only with the internal API) |
| signed limits file | see "Future: offline signed limits" | design only |

For a key, the **operator's** limit wins over a source's. A deny from any of
them denies. Rows are stored per organization and origin in `tenant_limits`
and `tenant_feature_denies`; a source never sees or changes another origin's
rows.

### Over-limit behaviour (one rule)

`limits.AllowAddition(limit, used, delta)` is the only over-limit rule:

- A limit refuses **new additions** only. Lowering it (by the operator, the
  control plane or, later, a license) never deletes, disables or signs out
  anything, and never stops work already running. The organization is flagged
  `over_limit` and additions of that kind are refused until usage is under
  the limit again.
- A feature that becomes denied keeps **read access for 30 days**
  (`limits.GracePeriod`): reads and export work, writes are refused, its jobs
  stop. Then it is off. Its data is kept. Every way to lose a feature goes
  through the same hook (`withGrace` in the service).

```
403 LIMIT_REACHED
The limit is 5 seats; 7 are in use. Remove some, or ask your administrator for more.
```

## Limit keys

| Key | What it counts |
|-----|----------------|
| `seats` | members who are not offboarded (a suspended member, or a sign-up awaiting approval, holds a seat) |
| `assets` | assets not deleted and not archived |
| `sensors` | the organization's own sensors that are not revoked (platform sensors never count) |
| `api_keys` | active API keys |
| `ci_trusts` | CI trust configurations |
| `invites_per_day` | invitations created in the last 24 hours |
| `platform_scans_per_day` | platform scans started a day (stored; enforced with platform scanning) |
| `platform_scans_concurrent` | platform scans running at once (stored; enforced with platform scanning) |
| `findings` | the organization's findings (a new fingerprint; a re-sighting counts nothing) |
| `orgs_per_user` | organizations one person owns, checked when they create one themselves; an instance setting (self-service defaults), never per organization |

`-1` means unlimited, the default of every key.

### Named features

Deniable features are the non-core top-level modules (by module id) plus
the named features below module level, each checked with `Allowed` at its
own seam. There are no named features yet. Core modules can never be
denied.

### Counting usage

Usage is read in one query over the cheap counts. Findings are the largest
table, so they are counted (a second query) **only while a findings limit
applies**; otherwise the `findings` row is `uncounted`. `Check` and
`Headroom` of an unlimited key count nothing.

## Self-service organizations

An organization a person creates themselves (create-first-team,
`POST /api/v1/tenants`) starts with the instance's **self-service default
limits** (`platform_settings` `self_service_default_limits`), written in the
same transaction as the organization. **Empty by default: no limits.** The
same setting holds `orgs_per_user`. Organizations created by the platform
(bootstrap-admin, the console, an approved access request) start with none.
Changing the defaults does not change existing organizations.

## Enforcement

The check sits at the **insert** (`internal/infra/postgres/limits_check.go`),
so every path that adds a row passes it, whatever the caller:

| Insert | Key | Paths it covers |
|--------|-----|-----------------|
| `TenantRepository.CreateMembership`, `AcceptInvitationTx` | `seats` | invitation accept (both endpoints), SSO and federated JIT, SCIM create, administrator-created users, direct adds |
| `TenantRepository.CreateInvitation` | `invites_per_day` | invitation create |
| `AssetRepository.Create` | `assets` | asset create, discovery that creates one asset |
| `AssetRepository.UpsertBatch` | `assets` (only the batch's assets that do not exist yet) | ingest: a batch over the limit is refused **whole** with the limit error, never dropped silently; re-ingesting existing assets is never refused |
| `SensorRepository.Create` | `sensors` (not platform sensors) | sensor create, bootstrap registration |
| `SensorPairingRepository.Approve` (new sensor, not a re-pair) | `sensors` | sensor pairing |
| `APIKeyRepository.Create` | `api_keys` | API key create |
| `CIRunRepository.CreateTrustConfig` | `ci_trusts` | CI trust create |
| `FindingRepository.Create`, `CreateInTx` | `findings` | manual finding create, finding import, pentest findings |
| `FindingRepository.CreateBatchWithResult` | `findings` (only the batch's fingerprints the organization does not have yet) | ingest: new findings are admitted in report order up to the headroom; **each one over it is refused on its own** (a per-item error: v1 `errors`, v2 `finding_not_stored` item error), while the report's assets, the other findings and every re-sighting of an existing finding are still stored. The report is not failed or retried. When the limit cannot be read, every new finding of the batch is refused the same way (fail-closed). |

Not checked: the first owner of an organization (its creation, and the
console's first-owner account), and re-activating an existing row.

Answers: 403 `LIMIT_REACHED` with the message above on the management API;
SCIM answers 403 with the message as `detail`; an SSO sign-up into an
organization with no free seat answers 403 `LIMIT_REACHED` "This organization
has no free seat for you" (no usage numbers, the person is not a member yet).
Every refusal increments `openctem_limit_refusals_total{key}`.

The check reads usage before the insert, outside its transaction, so two
concurrent additions at limit-1 can both pass. The limit is a capacity cap,
not a security boundary; that overshoot is accepted.

## Who changes what

| Endpoint | Who |
|----------|-----|
| `GET /api/v1/admin/settings/limits` | any administrator (self-service defaults and the configured sources) |
| `PUT /api/v1/admin/settings/limits` | **super_admin** + a fresh authenticator code; version read (409 when stale); audited **critical** |
| `GET /api/v1/admin/tenants/{id}/limits` | any administrator (limits with origin and reason, usage, denies) |
| `PUT/DELETE /api/v1/admin/tenants/{id}/limits/{key}` | **ops_admin+**, audited high (value, reason, optional expiry) |
| `GET /api/v1/admin/tenants/{id}/modules` | any administrator |
| `PUT/DELETE /api/v1/admin/tenants/{id}/modules/{module}/deny` | **ops_admin+** + reason + a fresh authenticator code, audited high |
| `GET /api/v1/organization/limits` | the organization's owners and admins: only the limits that apply and the unavailable features, without operator notes; `applies: false` when nothing applies |

The operator can only edit rows of origin `operator`. Rows of origin
`control_plane` are shown in the console as set by the service operator.

## Future: offline signed limits (design only, not built)

A self-hosted install gets every feature, and nothing here changes that.
Limits that arrive as a signed file instead of through the console or the
internal API fit as a third source, with no change to any check:

- A **signed offline license file** (Ed25519; the verifying public key
  compiled into the core; no activation and no phone-home, so air-gapped
  installs work).
- Its payload is limits and denies: per instance (applied to every
  organization) and, optionally, per organization id, plus an expiry.
- A `licenseSource` implements `limits.Source`: it verifies the signature at
  start and on reload, and yields rows like any other source. An invalid or
  missing file yields nothing (the default unlimited behaviour), never a
  crash.
- Expiry reuses the over-limit rule: the license's limits and denies stay in
  force (no new additions over them, denied features in read-only grace),
  nothing is deleted, and running work continues.
- Every check already goes through the entitlement service with named keys,
  so a license needs no new seam. The guard test keeps it that way.

## Code map

- `pkg/domain/limits`: keys, `Limits`, `Limit`, `FeatureDeny`, origins,
  `Source`, `NoneSource`, `AllowAddition`, `ErrLimitReached`, `GracePeriod`.
- `internal/app/entitlement`: the service (`service.go`), feature denies and
  grace (`features.go`), the control-plane source and write (`sources.go`).
- `internal/infra/postgres/limits_repository.go`: storage and usage counts,
  every query scoped by `tenant_id`; `limits_check.go`: the insert seam.
- `internal/infra/http/handler/limits_handler.go`: console and organization
  endpoints; `WriteLimitError` (403 `LIMIT_REACHED`).
- Migration `per_organization_limits` (002291): moved every organization's
  earlier limits and excluded modules to operator rows, then dropped the old
  tables.

Modules and their grace are described in [modules.md](modules.md) and
[RFC-064](../rfcs/RFC-064-modules-entitlements-preferences.md); the idle
policy (off by default) in [idle-workspaces.md](idle-workspaces.md).
