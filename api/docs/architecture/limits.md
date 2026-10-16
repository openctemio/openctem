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
| control plane | rows of origin `control_plane`, written through the [internal API](#internal-entitlements-api) of a hosted service | shipped (enabled only with the internal API) |
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
| `lifecycle_sub_statuses` | the organization's finding sub-statuses that are not archived ([RFC-110](../rfcs/RFC-110-tenant-lifecycles.md)) |
| `lifecycle_schemes` | its finding lifecycle schemes that are not archived |
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

**Self-service sign-up requires starting limits.** A public sign-up must
never hand out unlimited organizations by accident, so while sign-up is
`self_service` (`TENANT_CREATION_MODE`, or the console sign-up policy):

- the API refuses to start, and the console refuses to switch sign-up to
  self-service (409), unless starting limits are configured;
- configured means one of: a saved console setting (System > Limits, even an
  empty one), `SELF_SERVICE_START_LIMITS` (a JSON object of limits, or
  `unlimited` for an explicit choice of none), or the internal entitlements
  API of a hosted service (its control plane sets them);
- the console setting wins over the environment value.

An `admin_only` installation (the default) needs none of this.

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
| `findinglifecycle.Service.CreateSubStatus`, `CreateScheme` | `lifecycle_sub_statuses`, `lifecycle_schemes` | finding lifecycle catalog |
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

A hosted service can set `ACCOUNT_PORTAL_URL` (an absolute https URL): when a limit or deny applies, `GET /api/v1/organization/limits` returns it as `account_portal_url` and Usage & limits links to it. Unset (the default) there is no link anywhere.

The operator can only edit rows of origin `operator`. Rows of origin
`control_plane` are shown in the console as set by the service operator.

## Internal entitlements API

A hosted service runs a private control plane that decides each
organization's limits. It talks to the core only through this API. A
self-hosted install leaves it off (the default) and never needs it.

**Transport and trust**

- A separate listener, `INTERNAL_API_ADDR` (empty: off). Expose it on a
  private network only, never through the public gateway. The address must be a
  loopback or private IP (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `fc00::/7`): every-interface, public and link-local addresses and hostnames
  are refused at start unless `INTERNAL_API_ALLOW_ALL_INTERFACES=true` (for a
  container network with no published port).
- mTLS, TLS 1.3 only: a client certificate chaining to
  `INTERNAL_API_CLIENT_CA` is required in the handshake.
- Plus `Authorization: Bearer <token>` on every request: `EdDSA` (Ed25519)
  signed by a key in `INTERNAL_API_JWT_PUBLIC_KEYS` (two during rotation),
  `iss` = `INTERNAL_API_JWT_ISSUER`, `aud` = `openctem-core`, lifetime at most
  5 minutes, not issued in the future, a single-use `jti` (remembered in
  Redis so every replica refuses a replay; the API does not start without
  Redis), a `sub` naming the calling service, and `scope`
  with `limits:write`, `orgs:provision` or `usage:read`.
- Any failure answers 401 with no detail (the reason is logged). A missing
  scope is 403. 20 requests a second per calling service. Bodies are capped
  at 64 KiB and unknown JSON fields are refused.
- Every write is in the platform audit log as actor `control-plane`, with the
  `sub`, the `jti` and the reason. Idle policy changes also go to the
  organization's own log.
- Least privilege: there is no endpoint for findings, assets, members or
  any other organization content. Usage is aggregate counts, and
  provisioning returns ids only (never a set-password link).
- Turning the API on also turns on the control-plane source. Without it,
  rows of origin `control_plane` are ignored.

**Endpoints** (base `/internal/v1`)

| Endpoint | Scope | Does |
|----------|-------|------|
| `GET /catalog` | any | the limit keys and deniable features |
| `PUT /organizations/{id}/entitlements` `{limits, denied_features, reason}` | `limits:write` | replaces every control-plane limit and deny of the organization in one transaction; newly denied modules start the read-only grace |
| `PUT /organizations/{id}/idle-policy` `{enabled, reason}` | `limits:write` | turns the idle policy on or off |
| `PUT /self-service-limits` `{limits, reason}` | `limits:write` | replaces the self-service default limits (and `orgs_per_user`), so organizations people create themselves start with them |
| `POST /organizations` `{name, slug, owner_email, owner_name?, limits, denied_features, idle_policy, reason}` | `orgs:provision` | creates the organization, its owner (a new account that gets the set-password email), and the limits, denies and idle policy in the same transaction; 409 `CONFLICT` when the slug is taken; 409 `OWNER_ACCOUNT_EXISTS` when the email already has an account (nobody becomes an owner on someone else's request: that person signs in and creates the organization, which starts with the self-service limits) |
| `GET /organizations/{id}/usage[?include=findings]` | `usage:read` | aggregate counts |
| `GET /usage?after=<id>&limit=<1..500>` | `usage:read` | every organization in id order with `created_at` and its counts; `next` pages |

The control plane can only set limits, set denies and turn on the idle
policy. Every one of these blocks additions or makes data read-only: nothing
it can call deletes an organization or its data.

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
- `internal/infra/http/internalapi`: the internal API (token verifier,
  replay cache, listener and endpoints); `cmd/server/internal_api.go` wires
  it.
- Migration `per_organization_limits` (002834): moved every organization's
  earlier limits and excluded modules to operator rows, then dropped the old
  tables.

Modules and their grace are described in [modules.md](modules.md) and
[RFC-064](../rfcs/RFC-064-modules-entitlements-preferences.md); the idle
policy (off by default) in [idle-workspaces.md](idle-workspaces.md).
