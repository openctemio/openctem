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

Admin API (platform admin console, RFC-022):
`GET`/`PUT`/`DELETE /api/v1/admin/tenants/{tenantId}/sso/saml`. The PUT
validates the certificate (parseable PEM X.509) and the role. On an
organization that has an owner, the PUT does **not** change the live config: it
stores a pending change (202) that an owner approves or rejects (RFC-022
revision 8; see `sso-authentication.md`). The owner sees the new signing
certificate's SHA-256 to compare with their IdP. An organization without an
owner yet gets it applied directly.

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
- the session is stamped `auth_method = saml` and `idp_tenant_id = <this
  organization>`: it counts as an SSO sign-in (exempt from SSO enforcement and
  the 2FA requirement) for this organization only. Exchanged for any other
  organization the account belongs to, it is handled like a password session —
  see [sso-authentication.md](sso-authentication.md#how-a-sessions-login-method-is-recorded);
- an **existing** account is admitted only when it is already a member of the
  organization **and** its email domain is DNS-verified for that organization.
  Membership alone is not enough: users are global, an organization can make
  someone a member (accepted invitation, SCIM, admin add) without owning their
  identity, and the session is exchangeable for every organization the account
  belongs to. Without the domain check, an organization holding its own IdP
  signing key could sign in as any passwordless member and pivot into their
  other organizations;
- a brand-new email is admitted only through just-in-time provisioning:
  `auto_provision` on, the email domain DNS-verified for the organization, and
  inside the organization's `Security.AllowedDomains` (RFC-025). Otherwise the
  login is refused before any account is created; the membership gets
  `default_role` (default `viewer`; `owner` is coerced to `viewer`);
- issue the OpenCTEM session (reuses the SSO `createSession`).

The SAML ACS (9e) calls this after validating the assertion. The ACS parses the
posted form itself (`r.ParseForm`, body capped at 1 MB): crewjam reads
`SAMLResponse` from `r.PostForm`, and before RFC-025 the form was never parsed,
so no SAML sign-in could succeed. The crypto
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

## Default role of just-in-time members

An SSO provider (OIDC or SAML) and the `SSO_ENTRA_DEFAULT_ROLE` fallback may
only provision **member** or **viewer** (owner decision B18). `admin` is
refused when the provider is saved, and a provider stored before this rule
with `admin` provisions viewers: an IdP misconfiguration must not mint
administrators. Admins are promoted explicitly.
