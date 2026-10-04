# SCIM 2.0 Provisioning

> Inbound user lifecycle: a tenant's IdP (Okta/Azure AD) creates, reads, and
> **deactivates** users in OpenCTEM over SCIM 2.0. RFC-009 Phase 9a/9b.

## Why

Before SCIM, users were created on first SSO login (JIT) or by manual
invitation, and offboarding only took effect when a session/JWT expired. SCIM
lets the IdP push the full lifecycle — most importantly **immediate
deprovisioning** (deactivation suspends the tenant membership, which revokes
sessions and clears the permission cache in the same call).

## Auth — per-tenant bearer token

The organization owner mints a SCIM token (shown once); the IdP presents it as
`Authorization: Bearer <token>` on every `/scim/v2` request.

- Tokens are stored as **peppered HMAC-SHA256** hashes (`crypto.HashTokenPeppered`,
  pepper = `APP_ENCRYPTION_KEY`) — a DB leak without the pepper can't be
  brute-forced. The plaintext (`oct_scim_…`) is returned only at creation.
- `middleware.SCIMAuth` validates the token and puts the **resolved tenant id**
  in context. One token = one tenant, so every SCIM handler is tenant-isolated
  by construction — the tenant is never read from the request body.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/scim-tokens` | JWT, owner/admin | list a tenant's SCIM tokens |
| POST/DELETE | `/api/v1/scim-tokens` | JWT, **owner only** | mint / revoke a tenant's SCIM token |
| GET | `/scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | SCIM bearer | discovery |
| GET | `/scim/v2/Users?filter=userName eq "x"` | SCIM bearer | list / filter |
| POST | `/scim/v2/Users` | SCIM bearer | provision (find-or-create user + membership) |
| GET/PUT/PATCH/DELETE | `/scim/v2/Users/{id}` | SCIM bearer | read / replace / patch-active / deprovision |

## Mapping to the domain

- `id` is the OpenCTEM user id; every operation is scoped to the token's tenant
  via the user's **membership** in that tenant.
- **Create** (`POST /Users`): `userName`/`emails` → normalised lowercase email →
  find-or-create a passwordless local user (the same "invited, not yet logged
  in" state, so SSO/SAML can later claim it) → add an active membership
  (`role=member`). Idempotent: an existing active member returns `200`, a new
  membership `201`. An email that **already has an account** but is not yet a
  member is attached only when the organization has DNS-verified its domain;
  otherwise the response is `409 uniqueness` and the person must be invited.
  Attaching an existing account needs its owner's consent, the same rule as
  administrator-created accounts; without it any organization could enroll any
  person by email (and learn their user id).
- **Deactivate** (`PATCH active:false`, `DELETE`): suspends the membership via
  `TenantService.SuspendMember`, which **revokes the user's sessions immediately
  and clears the permission cache** — true 0-second offboarding. The global user
  record is retained (other tenants unaffected).
- **Reactivate** (`PATCH active:true`): un-suspends the membership.
- `active` in any SCIM resource reflects the membership (suspended → `active:false`).

## Guarantees

- **Tenant isolation** — tenant comes from the bearer token, never the body; the
  user must be a member of that tenant or operations return SCIM `404`.
- **Audit** — membership changes flow through `TenantService` with a SCIM system
  audit context, so create/suspend/reactivate/role changes are logged. Every
  entry written during a SCIM request also carries the token that made it
  (`metadata.auth_method = scim_token`, `scim_token_id`, `scim_token_prefix`;
  `audit.WithSCIMTokenActor`, set by `SCIMAuth`). Role changes are severity High.
- **SCIM error envelope** — RFC-7644 `…:Error` with `status`/`scimType`;
  `PATCH` rejects unsupported paths with `400 invalidPath` rather than silently
  ignoring them.

## Code map

| Piece | Where |
|-------|-------|
| Token entity + repo iface | `pkg/domain/scimtoken/entity.go` |
| Token persistence | `internal/infra/postgres/scim_token_repository.go`, migration `000179_scim_tokens` |
| Token service (mint/revoke/authenticate) | `internal/app/scim/token_service.go` |
| Provisioning service | `internal/app/scim/provisioning.go` |
| Bearer-token middleware | `internal/infra/http/middleware/scim_auth.go` |
| SCIM handlers | `internal/infra/http/handler/scim_handler.go` |
| Token admin handler | `internal/infra/http/handler/scim_token_handler.go` |
| Routes | `internal/infra/http/routes/scim.go` |

## Groups → role mapping (Phase 9c)

`/scim/v2/Groups` (create/read/list/PUT/PATCH/DELETE) lets the IdP push groups
whose membership drives a user's **tenant role**:

- A group whose `displayName` (case-insensitive) is `member` or `viewer` maps
  its members to that role. Other groups (e.g. "Engineering", and also a group
  named "admin") are stored but don't affect roles until they are mapped.
- **Configurable mapping** — because real IdPs name groups arbitrarily (e.g.
  "Acme-OpenCTEM-Admins"), any group display name can be mapped to a role via
  `GET`/`PUT /api/v1/scim-tokens/group-mappings` (JWT admin, body
  `{"mappings": {"Acme-OpenCTEM-Admins": "admin"}}`). A mapping takes precedence
  over the name-match default; `owner` is rejected. Saving re-reconciles all
  current group members immediately, as the person who saved (so the owner-only
  rule for changing an administrator applies to them). Each save is audited
  (`scim.group_mappings_updated`, severity High, before/after per group).
- **The admin role is the owner's call** (owner-only rule for changing
  administrators, 23b S-H1):
  - adding, changing or removing a mapping **to `admin`** is owner only
    (`403` for an administrator; checked against the membership table inside
    the write transaction). Administrators keep managing member/viewer mappings;
  - each mapping records who set it and whether they were the owner
    (`configured_by`, `configured_by_owner`, migration `000830`). Only an
    owner-configured admin mapping grants admin. Mappings saved before
    `000830` are not owner-configured, so an existing admin mapping stops
    granting admin until the owner saves it again (nobody is demoted by the
    upgrade);
  - SCIM removes admin from someone only once the owner has configured at least
    one admin mapping. An administrator appointed by hand is never demoted by an
    identity-provider push.
- A user's **effective role** is the highest-privilege role-group they belong
  to (`admin` > `member` > `viewer`); belonging to none defaults to `member`.
  `owner` is **never** assignable via SCIM, and the owner is never re-roled.
- Group membership is **authoritative** within those rules: adding a user to an
  owner-mapped admin group promotes them; removing them from their last
  role-group reverts to `member`. Every add/remove/replace/delete reconciles
  affected users' roles through `TenantService.UpdateMemberRole` (full audit +
  permission-cache invalidation).
- PATCH supports both **Okta** (member value-arrays) and **Azure AD**
  (`members[value eq "id"]` path filters) styles.

Code: `pkg/domain/scimgroup`, `internal/app/scim/groups.go`,
`internal/infra/postgres/scim_group_repository.go`,
`internal/infra/http/handler/scim_group_handler.go`, migration `000180`.
Verified end-to-end against real Postgres
(`tests/integration/scim_groups_test.go`).

## Deferred (RFC-009)

- Admin **UI** to mint/revoke the token and show the SCIM base URL.
- **SAML 2.0** SP login (Phase 9d–9f).
