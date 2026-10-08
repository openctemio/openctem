# Plans and limits

An organization is on one plan: **Free**, **Pro** or **Enterprise**. A plan
caps what the organization may **add** (members, assets, sensors, ...). A
platform administrator edits the plan defaults in the console and can give one
organization a different limit (an override).

Design: research/71 (SaaS readiness), section 7.1 and the owner decisions of
2026-10-08.

## Limits

| Key | What it counts | Free default |
|-----|----------------|--------------|
| `seats` | members who are not offboarded (a suspended member, or a sign-up awaiting approval, holds a seat) | 5 |
| `assets` | assets not deleted and not archived | 500 |
| `sensors` | the organization's own sensors that are not revoked (platform sensors never count) | 2 |
| `api_keys` | active API keys | 5 |
| `ci_trusts` | CI trust configurations | 2 |
| `invites_per_day` | invitations created in the last 24 hours | 20 |
| `platform_scans_per_day` | platform scans started a day | 10 |
| `platform_scans_concurrent` | platform scans running at once | 1 |
| `free_teams_per_user` | Free organizations one person owns (checked when an organization is created) | 1 |

`-1` means unlimited. Pro and Enterprise start unlimited; a platform
administrator sets the Pro limits in the console before selling it.

Platform scanning stays off for Free organizations until the platform
scanning redesign (research/67) lands; the two scan quotas are stored now so
the console shows them.

## Which plan an organization is on

- `tenant_plans` (migration 001325) holds the plan.
- An organization without a row was created before plans existed and is
  **Enterprise** (no limits). The migration changes nothing for existing
  organizations.
- An organization a person creates themselves (onboarding create-first-team,
  `POST /api/v1/tenants`) starts on **Free**.
- An organization the platform administrator creates has no row (unlimited)
  until the administrator picks a plan.

## Effective limit

For each key: an active override for the organization if there is one,
otherwise the plan default. An override has a reason (required, up to 500
characters) and may expire; once expired it no longer applies and the plan
default does again.

## Lowering a limit never removes anything

A limit only refuses **new** additions. When a limit is lowered below what an
organization uses (a plan change, a lower default, an override), nothing is
deleted, disabled or signed out. The organization is flagged **over limit**
(`over_limit` on each key and on the summary) and every addition of that kind
is refused until usage is under the limit again:

```
403 PLAN_LIMIT
Your plan allows 5 seats; you use 7. Remove some, or ask your administrator for more.
```

## Enforcement

`entitlement.Service.Check(ctx, tenantID, key, delta)` is the one check. It is
**fail-closed**: when the plan, overrides or usage cannot be read the addition
is refused ("This could not be checked against your plan right now"). Every
refusal increments `openctem_plan_limit_refusals_total{key}`.

The check sits at the **insert** (`internal/infra/postgres/plan_limits.go`),
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
| `POST /api/v1/tenants` | `free_teams_per_user` | another self-service organization |

Not checked: the first owner of an organization (its creation, and the
console's first-owner account), and re-activating an existing row.

Answers: 403 `PLAN_LIMIT` with the message above on the management API; SCIM
answers 403 with the message as `detail`; an SSO sign-up into an organization
with no free seat answers 403 `PLAN_LIMIT` "This organization has no free seat
for you" (no usage numbers, the person is not a member yet).

The check reads usage before the insert, outside its transaction, so two
concurrent additions at limit-1 can both pass. The limit is a commercial cap,
not a security boundary; that overshoot is accepted.

## Who changes what

| Endpoint | Who |
|----------|-----|
| `GET /api/v1/admin/settings/plans` | any administrator |
| `PUT /api/v1/admin/settings/plans` | **super_admin** + a fresh authenticator code; version read (409 when stale); audited **critical**; the other administrators are emailed |
| `GET /api/v1/admin/tenants/{id}/plan` | any administrator (limits, usage, over-limit flag) |
| `PUT /api/v1/admin/tenants/{id}/plan` | **ops_admin+**, audited high |
| `PUT/DELETE /api/v1/admin/tenants/{id}/plan/overrides/{key}` | **ops_admin+**, audited high (value, reason, expiry) |
| `GET /api/v1/organization/plan` | the organization's owners and admins (Settings > Plan & usage) |

The defaults are stored in `platform_settings` under `plan_limits`; until an
administrator saves them the built-in defaults above apply.

## Code map

- `pkg/domain/plan`: plans, keys, defaults, overrides, `ErrLimitReached`.
- `internal/app/entitlement`: effective limits, `Check`, `CheckFreeTeam`,
  console changes (audit, notification).
- `internal/infra/postgres/plan_repository.go`: storage and usage counts,
  every query scoped by `tenant_id`.
- `internal/infra/http/handler/plan_handler.go`: console and organization
  endpoints; `WritePlanLimitError` (403 `PLAN_LIMIT`).
