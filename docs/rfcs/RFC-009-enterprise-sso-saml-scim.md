# RFC-009 — Enterprise SSO: SAML 2.0 + SCIM 2.0 provisioning

> Status: **Proposed**. Adds enterprise identity to OpenCTEM beyond the current
> OIDC/OAuth SSO (`internal/app/auth/sso.go`): inbound **SAML 2.0** login and
> **SCIM 2.0** automated user provisioning/deprovisioning.

## Why

OpenCTEM today authenticates against IdPs via per-tenant OIDC/OAuth (Entra,
Okta, Google) — see `docs/architecture/sso-authentication.md`. Two enterprise
gaps remain:

1. **SAML 2.0** — many enterprises standardise on SAML, not OIDC. Without it,
   those orgs cannot use their IdP with OpenCTEM.
2. **SCIM 2.0** — today users are created on first SSO login (JIT) or by manual
   invitation. There is no *automated* lifecycle: when HR offboards someone in
   the IdP, their OpenCTEM access is not revoked until their session/JWT expires.
   SCIM lets the IdP push create/update/**deactivate** directly.

This RFC is split so each half ships independently. **SCIM is recommended
first** — it is pure REST/JSON, fully unit-testable without an external IdP, and
delivers the highest security value (automated deprovisioning).

---

## Decisions required (the reason this is an RFC, not a PR)

1. **SAML library.** Pure-Go options: `github.com/crewjam/saml` (mature SP
   toolkit, BSD-2) is the recommendation. It handles XML signature verification
   — the part that must be exactly right or it is a critical auth bypass. We do
   **not** hand-roll SAML crypto. This adds a non-trivial dependency tree.
2. **End-to-end IdP testing.** SAML assertion flows and SCIM provisioning must
   be validated against a real Okta/Azure AD test tenant before GA. Unit tests
   (signed-assertion fixtures, SCIM request/response) cover the logic; a staging
   IdP covers the integration. This work is gated on access to a test tenant.

These are genuinely the operator's call, hence an RFC.

---

## Part 1 — SCIM 2.0 provisioning (recommended first)

Inbound: the tenant's IdP is the system of record and pushes user lifecycle to
OpenCTEM over the [SCIM 2.0](https://datatracker.ietf.org/doc/html/rfc7644) REST
protocol.

### Auth — per-tenant SCIM bearer token

Reuse the existing API-key crypto rather than inventing a token scheme:

- New entity `scim_token` (mirrors `pkg/domain/apikey`): `id`, `tenant_id`,
  `token_hash`, `token_prefix`, `status`, `created_at`, `last_used_at`.
- Store `crypto.HashTokenPeppered(plaintext, pepper)` (HMAC-SHA256, pepper =
  `APP_ENCRYPTION_KEY`); verify with `crypto.VerifyTokenHashAny` (constant-time,
  `pkg/crypto/hash.go:93`). Plaintext shown once on creation.
- Middleware `ScimAuth`: extract `Authorization: Bearer <token>` (mirror
  `middleware.extractToken`, `unified_auth.go:73`), hash, `GetByHash`, confirm
  `status == active`, put `tenant_id` in context. One token = one tenant →
  tenant isolation by construction.

### Endpoints (`/scim/v2`, NOT under `/api/v1`)

| Method | Path | Action |
|--------|------|--------|
| GET | `/scim/v2/ServiceProviderConfig` | capabilities (patch=true, filter=true, bulk=false) |
| GET | `/scim/v2/ResourceTypes`, `/Schemas` | discovery |
| GET | `/scim/v2/Users?filter=userName eq "x"` | list/filter (IdP reconciliation) |
| GET | `/scim/v2/Users/{id}` | read |
| POST | `/scim/v2/Users` | **provision**: find-or-create user + tenant membership |
| PUT | `/scim/v2/Users/{id}` | replace |
| PATCH | `/scim/v2/Users/{id}` | **PatchOp** — primarily `active:false` → deprovision |
| DELETE | `/scim/v2/Users/{id}` | deprovision |
| GET/POST/PATCH/DELETE | `/scim/v2/Groups...` | (phase 2) role mapping via groups |

Register via `router.Group("/scim/v2", ..., scimAuth)` — root-level groups are
already used (`/health`, `/openapi.yaml`), so this is conventional.

### Mapping to the domain (reuse existing surface)

- **Create** (`POST /Users`): `userName`/emails → `userRepo.GetByEmail` (email
  is globally unique, lowercased). If absent, create the user (same path as SSO
  JIT, `sso.go:705 findOrCreateUser`), then
  `tenantdom.NewMembership(userID, tenantID, role, nil)` +
  `CreateMembership`. Default role `member`; never `owner`
  (`tenant.InvitableRoles`).
- **Deactivate** (`PATCH active:false` / `DELETE`): `membership.Suspend(by)`
  (`membership.go:200`) via `TenantService`, which already **revokes sessions
  immediately and clears the permission cache** — true 0-second offboarding.
  Reactivate on `active:true` → `membership.Reactivate()`.
- **Role** is a string (`owner|admin|member|viewer`), not a UUID
  (`tenant/role.go`). Group→role mapping is phase 2.
- Email is the SCIM `externalId` anchor; store the IdP `externalId` in
  membership/user metadata for stable re-lookup.
- Every create/deactivate emits an audit event
  (`audit.NewSuccessEvent(ActionMemberAdded/Suspended, ...)`) with
  `scim_operation` metadata.

### SCIM correctness details

- Responses use `urn:ietf:params:scim:schemas:core:2.0:User`, `meta.resourceType`,
  `meta.location`, ETag-style `meta.version` (optional).
- Errors use `urn:ietf:params:scim:api:messages:2.0:Error` with SCIM `status`
  + `scimType` (e.g. `409 uniqueness`).
- `PATCH` implements RFC-7644 §3.5.2 PatchOp (`op: replace/add/remove`,
  `path`) — scope MVP to `replace value.active` and role; reject unsupported
  paths with `400 invalidPath` rather than silently ignoring.
- List supports `filter=userName eq "..."` + `startIndex`/`count` (IdPs poll
  this to reconcile).

### Testing (no external IdP needed)

Table-driven handler tests posting real Okta/Azure SCIM payloads; assert user +
membership created, `active:false` suspends + revokes sessions, uniqueness →
`409`, bearer-token auth rejects bad/[]/cross-tenant tokens, filter/pagination.

### Phasing

- **9a** — SCIM token entity + repo + migration + `ScimAuth` middleware + admin
  endpoint to mint/revoke a tenant SCIM token (+ UI).
- **9b** — `/scim/v2/Users` (create/read/list/filter/PATCH-active/DELETE) +
  ServiceProviderConfig/Schemas + tests.
- **9c** — `/scim/v2/Groups` + group→role mapping.

---

## Part 2 — SAML 2.0 (SP) login

Inbound SP-initiated and IdP-initiated SAML login, parallel to the OIDC SSO
flow, reusing the same identity-resolution tail.

### Components

- Per-tenant SAML config (extend `identityprovider` with a `saml` provider:
  IdP SSO URL, IdP signing cert/metadata URL, SP entityID, audience).
- `GET /api/v1/auth/saml/{org}/metadata` — SP metadata XML for IdP setup.
- `GET /api/v1/auth/saml/{org}/login` — build AuthnRequest, redirect to IdP.
- `POST /api/v1/auth/saml/{org}/acs` — Assertion Consumer Service: **verify the
  assertion signature against the tenant's IdP cert** (via `crewjam/saml` —
  not hand-rolled), validate audience/recipient/NotOnOrAfter/InResponseTo
  (replay), extract the email/NameID, then reuse `findOrCreateUser` +
  auto-provision + `createSession` exactly like `sso.go:HandleCallback`.

### Security (the non-negotiables)

- Signature verification on the assertion (and/or response) is mandatory and
  fail-closed; reject unsigned. Validate `Audience`, `Recipient`,
  `NotOnOrAfter`, and `InResponseTo` against a stored request id (replay guard,
  same role the OIDC `nonce` plays).
- Outbound metadata/IdP fetches go through `httpsec.SafeHTTPClient` (SSRF guard),
  as the OIDC path already does.

### Testing

Mint a self-signed SAML assertion with a test keypair in unit tests (the same
approach used for the OIDC id_token verifier in
`internal/app/auth/oidc_verifier_test.go`): assert valid → session; tampered
signature / wrong audience / expired / replayed → rejected. Full flow validated
against a staging Okta/Azure SAML app before GA.

### Phasing

- **9d** — SAML config model + SP metadata endpoint.
- **9e** — AuthnRequest + ACS with signature/condition validation + identity
  mapping + tests.
- **9f** — IdP-initiated flow + SLO (single logout), if required.

---

## Out of scope

- SAML as an IdP (OpenCTEM issuing assertions to other apps).
- SCIM bulk operations (`/Bulk`).
- Just-in-time *role* changes from SAML attribute statements (phase with 9c).

## Where it lives

```
pkg/domain/scimtoken/            SCIM bearer-token entity (mirrors apikey)
internal/app/scim/               SCIM provisioning service (maps to user+membership)
internal/infra/http/handler/     scim_handler.go
internal/infra/http/middleware/  scim_auth.go
internal/app/auth/saml.go        SAML SP flow (parallels sso.go)
migrations/                      scim_tokens (+ saml provider config columns)
```

Conventions: PRs target `develop`; phased PRs reference this RFC number.
