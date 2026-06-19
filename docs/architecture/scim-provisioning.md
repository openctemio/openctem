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

A tenant admin mints a SCIM token (shown once); the IdP presents it as
`Authorization: Bearer <token>` on every `/scim/v2` request.

- Tokens are stored as **peppered HMAC-SHA256** hashes (`crypto.HashTokenPeppered`,
  pepper = `APP_ENCRYPTION_KEY`) — a DB leak without the pepper can't be
  brute-forced. The plaintext (`oct_scim_…`) is returned only at creation.
- `middleware.SCIMAuth` validates the token and puts the **resolved tenant id**
  in context. One token = one tenant, so every SCIM handler is tenant-isolated
  by construction — the tenant is never read from the request body.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST/GET/DELETE | `/api/v1/scim-tokens` | JWT, owner/admin | mint / list / revoke a tenant's SCIM token |
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
  membership `201`.
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
  audit context, so create/suspend/reactivate are logged.
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

- A group whose `displayName` (case-insensitive) is a tenant role — `admin`,
  `member`, or `viewer` — maps its members to that role. Non-role-named groups
  (e.g. "Engineering") are stored but don't affect roles.
- **Configurable mapping** — because real IdPs name groups arbitrarily (e.g.
  "Acme-OpenCTEM-Admins"), an admin can map any group display name to a role via
  `GET`/`PUT /api/v1/scim-tokens/group-mappings` (JWT admin, body
  `{"mappings": {"Acme-OpenCTEM-Admins": "admin"}}`). A mapping takes precedence
  over the name-match default; `owner` is rejected. Saving re-reconciles all
  current group members immediately.
- A user's **effective role** is the highest-privilege role-group they belong
  to (`admin` > `member` > `viewer`); belonging to none defaults to `member`.
  `owner` is **never** assignable via SCIM.
- Group membership is **authoritative**: adding a user to an `admin` group
  promotes them; removing them from their last role-group reverts to `member`.
  Every add/remove/replace/delete reconciles affected users' roles through
  `TenantService.UpdateMemberRole` (full audit + permission-cache invalidation).
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
