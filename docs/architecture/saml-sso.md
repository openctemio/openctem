# SAML 2.0 SSO (Service Provider)

> Per-tenant SAML login, parallel to the OIDC SSO path. RFC-009 Phase 9d/9e.
> OpenCTEM acts as a SAML **Service Provider (SP)**; the tenant's IdP (Okta,
> Microsoft Entra ID, etc.) is the Identity Provider.

## Status

- **9d (shipped)** — per-tenant config + SP metadata + admin CRUD + the shared
  federated-login seam.
- **9e (next)** — SP-initiated login (`/login`) + Assertion Consumer Service
  (`/acs`): build the IdP-side `ServiceProvider` from the stored certificate,
  validate the assertion signature + conditions + `InResponseTo` (replay), then
  issue a session via `SSOService.CompleteFederatedLogin`. This is the
  replay-sensitive, security-critical step and needs a live IdP to validate.

## Config (9d)

`saml_providers` (migration 000182), one row per tenant, **disabled by
default** — an operator enables SAML only after validating it against their IdP:

| Field | Meaning |
|-------|---------|
| `idp_entity_id`, `idp_sso_url` | IdP issuer + SSO redirect endpoint |
| `idp_certificate` | IdP signing cert (PEM) — the trust anchor for assertion signatures |
| `allowed_domains` | email-domain allow-list (empty = any) |
| `default_role` | role for auto-provisioned users (`admin`/`member`/`viewer`; never `owner`) |
| `auto_provision`, `enabled` | provision-on-login + master switch |

Admin API (JWT, owner/admin): `GET`/`PUT`/`DELETE /api/v1/settings/saml`. The
PUT validates the certificate (parseable PEM X.509) and the role.

## SP metadata

`GET /api/v1/auth/saml/{org}/metadata` (public) returns the SP metadata XML the
admin registers with their IdP. The SP entity id / ACS URL are **derived from
the request host** (honoring `X-Forwarded-Proto`/`-Host`) so they always match
the deployment — `…/api/v1/auth/saml/{org}/{metadata,acs}`.

## Federated-login seam (shared with future SAML ACS)

`SSOService.CompleteFederatedLogin(tenant, email, name, defaultRole, autoProvision)`
is the shared tail for any externally-authenticated identity:

- find-or-create a **claimable passwordless** local user (same shape as an
  invite / SCIM-provisioned user, so it can later set a password or be claimed);
- **account-takeover guard** — a password-backed local account is **rejected**
  (a federated assertion must not log into someone's password account);
- auto-provision tenant membership (when enabled; `owner` is coerced away);
- issue the OpenCTEM session (reuses the SSO `createSession`).

The SAML ACS (9e) calls this after validating the assertion. The crypto
(XML-dsig signature verification) is handled by `github.com/crewjam/saml`, not
hand-rolled.

## Code map

| Piece | Where |
|-------|-------|
| Config domain + repo | `pkg/domain/samlprovider/`, `internal/infra/postgres/saml_provider_repository.go` |
| Service (config + metadata) | `internal/app/auth/saml.go` (`SAMLService`) |
| Federated-login seam | `internal/app/auth/sso.go` (`SSOService.CompleteFederatedLogin`) |
| HTTP | `internal/infra/http/handler/saml_handler.go`, routes in `routes/auth.go` |
| Migration | `000182_saml_providers` |
