# How to configure Microsoft Entra ID (Azure AD) SSO

> Operator how-to for wiring OpenCTEM to Microsoft Entra ID. Covers the two
> distinct Microsoft login paths, the Azure app-registration steps, the exact
> OpenCTEM env vars / admin-UI fields, the post-hardening requirements
> (`xms_edov` claim, redirect-URI allow-list, DNS-verified domains), the login
> flow, and troubleshooting — including the common **404 "Not Found"** on the
> login button.
>
> For the design/architecture reference (why each control exists), see
> [`sso-authentication.md`](../architecture/sso-authentication.md).

---

## 1. Which path do you want?

OpenCTEM has **two independent Microsoft/Entra login paths**. They do not share
config and are wired separately. Pick based on your goal.

| | **Path A — "Sign in with Microsoft" (social)** | **Path B — per-tenant Entra SSO** |
|---|---|---|
| Purpose | A generic social button on the login/onboarding page. Good for self-service onboarding of new users/orgs. | Enterprise SSO into **one specific organization (tenant)** using **that customer's own** Azure app registration. |
| Code | `internal/app/auth/oauth.go` | `internal/app/auth/sso.go` |
| Config source | Platform env: `OAUTH_MICROSOFT_*` | Per-tenant DB record (admin UI) **or** platform env fallback `SSO_ENTRA_*` |
| Authority | Multi-tenant `/common` (any Entra tenant can complete it) | The customer's directory (single-tenant GUID) — or `/common` if you must |
| Org binding | None — identity is the domain-verified email | Login is scoped to an org slug via `?org=<slug>` |
| JIT / auto-provision | N/A (creates a global user; onboarding assigns tenant) | Yes, gated by DNS-verified domains |
| Endpoints | `GET/POST /api/v1/auth/oauth/microsoft/{authorize,callback}` | `GET/POST /api/v1/auth/sso/entra_id/{authorize,callback}` |

Most enterprise deployments want **Path B**. Path A is optional and only needed
if you want a public "Sign in with Microsoft" button.

You can enable **both** at once — they don't conflict.

---

## 2. Azure portal: register the application

This is the same on the Azure side for both paths; the difference is only which
**redirect (reply) URI** you register and which OpenCTEM config you paste the
values into.

Let `FRONTEND` be your OpenCTEM UI origin (e.g. `https://app.example.com`; in
dev, `http://localhost:3000`).

1. **Azure portal → Microsoft Entra ID → App registrations → New registration.**
   - Name: e.g. `OpenCTEM SSO`.
   - Supported account types:
     - **Path B (recommended):** *Accounts in this organizational directory only*
       (single tenant). This pins logins to your directory.
     - **Path A** (or a multi-tenant Path B): *Accounts in any organizational
       directory*.
2. **Add a Redirect URI** (type **Web**). The URI the browser is sent back to is
   the **frontend callback**, not the API — the UI then POSTs the code to the API.
   Register the exact URL(s) for the path(s) you use:

   | Path | Redirect (reply) URI to register in Azure |
   |------|--------------------------------------------|
   | **Path B** — per-tenant Entra SSO | `FRONTEND/auth/sso/callback/entra_id` |
   | **Path A** — social Microsoft | `FRONTEND/auth/callback` |

   Example (prod): `https://app.example.com/auth/sso/callback/entra_id`.
   These must match **exactly** (scheme, host, port, path). A mismatch causes
   Azure error `AADSTS50011` (redirect URI mismatch).

3. **Certificates & secrets → New client secret.** Copy the secret **Value**
   (not the Secret ID) immediately — it is shown only once. Note its expiry and
   set a rotation reminder.
4. **Overview** — copy:
   - **Application (client) ID** → OpenCTEM `client_id` / `SSO_ENTRA_CLIENT_ID`.
   - **Directory (tenant) ID** → OpenCTEM `tenant_identifier` / `SSO_ENTRA_TENANT_ID`.
5. **API permissions** — the delegated **Microsoft Graph** scopes `openid`,
   `email`, `profile` (and `User.Read`) are sufficient. Grant admin consent if
   your directory requires it. No application (app-only) permissions are needed.
6. **REQUIRED — add the `xms_edov` optional ID-token claim.**
   **Token configuration → Add optional claim → Token type: ID → select
   `xms_edov` → Add.** If prompted to "turn on the Microsoft Graph email
   permission," accept.

   **Why this is mandatory:** `xms_edov` = "email domain owner verified."
   OpenCTEM trusts the `email` claim **only when `xms_edov == true`**. This is the
   fix for the **nOAuth** account-takeover class: on a multi-tenant authority a
   rogue directory can set a user's `mail`/`email` to a victim's address without
   owning the domain. A domain can be verified in exactly one Entra tenant, so a
   domain-owner-verified email is a reliable identifier. **If the claim is absent
   or false, OpenCTEM refuses the login (fail-closed)** — this applies to Path A
   always, and to Path B for Entra logins.

   > Expected, by-design refusals once `xms_edov` is required: **personal
   > Microsoft accounts** (outlook.com / live.com / hotmail.com) and **B2B guest
   > users** whose email domain isn't verified in the signing directory will be
   > refused. Work/school accounts on a domain the tenant owns get
   > `xms_edov == true` and sign in normally. To admit specific external
   > identities, use **Path B** with an explicit domain allow-list.

---

## 3. Configure OpenCTEM

### Path A — "Sign in with Microsoft" (env)

Set on the API service and restart:

```bash
OAUTH_ENABLED=true                 # top-level social OAuth switch (default true)
OAUTH_MICROSOFT_ENABLED=true
OAUTH_MICROSOFT_CLIENT_ID=<application-client-id>
OAUTH_MICROSOFT_CLIENT_SECRET=<client-secret-value>
# Scopes default to: openid email profile User.Read
OAUTH_MICROSOFT_SCOPES=openid,email,profile,User.Read

# The frontend callback the browser returns to (must match the Azure reply URI
# for Path A and be a trusted origin). Default: http://localhost:3000/auth/callback
OAUTH_FRONTEND_CALLBACK_URL=https://app.example.com/auth/callback
```

The social button appears when `OAUTH_MICROSOFT_CLIENT_ID` **and**
`OAUTH_MICROSOFT_CLIENT_SECRET` are both set (`IsConfigured()`), OAuth is enabled,
and the OAuth handler is wired. `GET /api/v1/auth/oauth/providers` reports which
social providers are enabled.

### Path B — per-tenant Entra SSO (admin UI, recommended)

Each customer configures **their own** Azure app in OpenCTEM. As a **tenant
admin** (owner/admin), go to **Settings → Identity Providers** (backed by
`POST /api/v1/settings/identity-providers`, stored encrypted in
`tenant_identity_providers`).

Fields (request body of `POST /api/v1/settings/identity-providers`):

| Field | Value |
|-------|-------|
| `provider` | `entra_id` |
| `display_name` | Button label, e.g. `Sign in with Company SSO` |
| `client_id` | Application (client) ID |
| `client_secret` | Client secret **Value** (stored AES-256-GCM encrypted) |
| `tenant_identifier` | **Directory (tenant) ID** (GUID). Pin to your directory; avoid `common` unless you also set an allow-list. |
| `scopes` | `["openid","email","profile","User.Read"]` |
| `allowed_domains` | Email domains permitted, e.g. `["example.com"]`. Empty = any domain allowed to **log in**, but see JIT rules below. |
| `auto_provision` | `true` to create tenant membership on first login (still gated — see §4) |
| `default_role` | `member` or `viewer` (role granted to auto-provisioned users) |

The tenant's own active `entra_id` provider always wins over the env fallback.

### Path B — platform env fallback (optional, opt-in)

Instead of per-tenant DB config you can run **one shared** Entra app across
selected tenants via env. **This is opt-in and fail-closed** — post-P0 it does
nothing until you list the tenant slugs that may use it.

```bash
SSO_ENTRA_ENABLED=true
SSO_ENTRA_CLIENT_ID=<application-client-id>
SSO_ENTRA_CLIENT_SECRET=<client-secret-value>     # plaintext; env is the trust boundary
SSO_ENTRA_TENANT_ID=<directory-guid>              # default "common"
SSO_ENTRA_ALLOWED_DOMAINS=example.com,acme.com    # CSV; REQUIRED when TENANT_ID is common/organizations/consumers
SSO_ENTRA_DEFAULT_ROLE=member                     # default member
SSO_ENTRA_AUTO_PROVISION=true                     # default true
SSO_ENTRA_DISPLAY_NAME=Microsoft Entra ID

# P0 opt-in — CSV of tenant SLUGS allowed to use this shared fallback.
# EMPTY ⇒ the fallback is DISABLED for everyone (no button, no login).
SSO_ENTRA_ALLOWED_TENANTS=acme,globex
```

Fail-closed rules enforced by `envProvider()`:

- **`SSO_ENTRA_ALLOWED_TENANTS` is the master opt-in.** A tenant whose slug is
  not on the list sees no env button and cannot log in via the fallback. Empty
  list ⇒ disabled entirely.
- **A non-specific directory** (`common`, `organizations`, `consumers`, or empty)
  accepts any Microsoft directory, so:
  - `SSO_ENTRA_ALLOWED_DOMAINS` is **required** — if empty, the fallback is
    **refused** (logged: *"non-specific directory requires SSO_ENTRA_ALLOWED_DOMAINS"*).
  - **auto-provisioning is forced off** (users must be pre-invited).
- A **pinned** config (real directory GUID + a non-empty `AllowedDomains`) may
  auto-provision.

> `EntraSSOConfig.IsConfigured()` requires `SSO_ENTRA_ENABLED=true` + a client id
> + a client secret. `APP_ENCRYPTION_KEY` must be set in production so per-tenant
> secrets (and the PKCE verifier carried in `state`) are encrypted — see §8.

---

## 4. JIT auto-provisioning & DNS-verified domains (P1)

Letting a valid Entra login **create a new membership** in your org (JIT) is
gated so an authenticated stranger can't self-join. Existing members are never
affected.

The **primary gate is a DNS-verified domain.** A tenant admin proves the org
owns the email domain via a DNS TXT record; only then are that domain's users
auto-provisioned.

**Settings → Verified Domains** (`/api/v1/settings/verified-domains`, admin-only):

1. **Add domain** (`POST /api/v1/settings/verified-domains`) → OpenCTEM returns a
   TXT record to publish:

   | Field | Value |
   |-------|-------|
   | Host | `_openctem-verify.<domain>` (e.g. `_openctem-verify.example.com`) |
   | Type | `TXT` |
   | Value | `openctem-domain-verification=<token>` |

2. Publish that TXT record at your DNS provider.
3. **Verify** (`POST /api/v1/settings/verified-domains/{id}/verify`) — OpenCTEM
   does a live `LookupTXT` and marks the domain verified when the exact token is
   present.

Auto-provisioning decision (`jitProvisioningAllowed`), all branches fail-closed:

- The provider must have `auto_provision = true`.
- **Verified-domain gate (P1, when wired):** the email domain **must be
  DNS-verified** for the tenant. If the provider *also* set `allowed_domains`,
  the domain must be on that list too (admins may narrow further). A DNS lookup
  error ⇒ refuse.
- **Pre-wiring fallback (P0):** if the verified-domain verifier isn't wired, the
  domain must be on a **non-empty** `allowed_domains` list (empty ⇒ refuse).

If JIT isn't permitted, the login is refused with "not a member of this
organization" — the user must be **invited** first (Settings → Team →
Invitations). Also: with `AUTH_ALLOW_REGISTRATION=false`, a federated login can
only bind to an existing/pre-invited account — it will never create a brand-new
user.

---

## 5. PKCE & the redirect-URI allow-list (P1)

- **PKCE (RFC 7636, S256) is always on** for Path B. The verifier is encrypted
  (AES-256-GCM) inside the signed `state` and recovered at callback — so it works
  across replicas with no server-side store. A callback with a missing verifier
  is refused. (This is why `APP_ENCRYPTION_KEY` matters in production; in dev
  without it the encryptor is a no-op.)
- **`redirect_uri` is validated against an exact-match allow-list**
  (`SSO_ALLOWED_REDIRECT_URIS`) — OAuth 2.1 / RFC 9700 open-redirect defense.
  Origin (scheme+host+port) must match exactly; no wildcards, no suffix match;
  embedded credentials (`user:pass@host`) are rejected.

  ```bash
  # CSV of allowed frontend callback URLs/origins.
  SSO_ALLOWED_REDIRECT_URIS=https://app.example.com/auth/sso/callback/entra_id
  ```

  **If unset, it is derived** from origins already trusted elsewhere: your CORS
  allowed origins, `OAUTH_FRONTEND_CALLBACK_URL`, and `SMTP_BASE_URL` (each
  reduced to its exact origin). So the shipped UI callback works out of the box
  when those are set correctly; set `SSO_ALLOWED_REDIRECT_URIS` explicitly to
  tighten or when your callback origin isn't otherwise trusted.

---

## 6. The login flow (org-slug model)

Path B is **org-scoped**. A user reaches their org's login by slug:

```
https://app.example.com/login?org=<slug>
```

1. The UI calls `GET /api/v1/auth/sso/providers?org=<slug>` to render the org's
   SSO buttons (the tenant's own providers, plus the env-fallback button **only**
   if that tenant opted in).
2. Clicking a button hits `GET /api/v1/auth/sso/entra_id/authorize?org=<slug>&redirect_uri=<FRONTEND>/auth/sso/callback/entra_id`,
   which returns the Microsoft authorization URL (with signed `state`, `nonce`,
   PKCE `code_challenge`).
3. After Microsoft auth, the browser returns to
   `FRONTEND/auth/sso/callback/entra_id`; the UI POSTs the code to
   `POST /api/v1/auth/sso/entra_id/callback`. The API validates `state` + PKCE,
   exchanges the code, verifies the `id_token` (signature/issuer/audience/nonce +
   `xms_edov`), enforces the domain allow-list, provisions per §4, and issues an
   OpenCTEM session.

**To enable it for a tenant:** an admin (1) configures the Entra provider under
Settings → Identity Providers (or you opt the tenant into the env fallback), and
(2) verifies the email domain under Settings → Verified Domains so first-time
users auto-join. Then share `…/login?org=<slug>`.

---

## 7. Troubleshooting

### Clicking Microsoft / Entra login → **404 "Not Found"**

This is the #1 symptom and almost always means **the provider isn't configured
for that path/org**. `ErrSSOProviderNotFound` → HTTP 404 *"SSO provider not
configured"*; `ErrSSOTenantNotFound` → 404 *"Organization not found"*. Checklist:

1. **Org slug** — is `?org=<slug>` present and correct? A wrong/missing slug →
   404 "Organization not found."
2. **Path B, tenant config** — does the tenant have an **active** `entra_id`
   provider under Settings → Identity Providers? Inactive/absent + no env fallback
   ⇒ 404.
3. **Path B, env fallback** — if you rely on the env fallback, confirm **all** of:
   `SSO_ENTRA_ENABLED=true`, `SSO_ENTRA_CLIENT_ID`/`SSO_ENTRA_CLIENT_SECRET` set,
   **and the tenant's slug is on `SSO_ENTRA_ALLOWED_TENANTS`** (the P0 opt-in —
   empty list disables it for everyone). If `SSO_ENTRA_TENANT_ID` is
   `common`/empty, `SSO_ENTRA_ALLOWED_DOMAINS` must also be non-empty or the
   fallback is refused (check logs for the "non-specific directory requires…"
   warning).
4. **Path A social button** — the button only shows when
   `OAUTH_MICROSOFT_CLIENT_ID` **and** `OAUTH_MICROSOFT_CLIENT_SECRET` are set and
   `OAUTH_ENABLED=true`. If the OAuth handler isn't wired the `/auth/oauth/*`
   routes aren't registered → 404; a configured-but-disabled provider returns
   403 *"This OAuth provider is not configured"* instead.
5. **Restart** — env changes require an API restart to take effect.

### Login is refused after Microsoft auth ("id_token failed validation")

- **`xms_edov` missing/false** — the optional claim isn't on the app
  registration, so the email isn't domain-owner-verified and the login
  **fails closed**. Add it (Token configuration → optional claim → ID →
  `xms_edov`). Remember personal accounts / unverified-domain guests are refused
  by design.
- **No `openid` scope** — Entra returned no verifiable `id_token`; add `openid`
  to the provider scopes.
- **Issuer/audience/nonce mismatch** — the token's `tid`/issuer doesn't match the
  configured directory, or the flow was replayed. For a single-tenant config the
  token `tid` must equal `tenant_identifier`.

### `redirect_uri` rejected ("invalid redirect URI … not in allow-list")

The frontend callback isn't on the exact-match allow-list. Add it to
`SSO_ALLOWED_REDIRECT_URIS` (or ensure the origin is covered by your CORS
origins / `OAUTH_FRONTEND_CALLBACK_URL` / `SMTP_BASE_URL`, which seed the derived
list). It must match the URL the UI sends: `FRONTEND/auth/sso/callback/entra_id`.

### User authenticates but can't get in ("not a member of this organization")

JIT provisioning was refused (§4). Either **verify the email domain** (Settings →
Verified Domains) with `auto_provision=true`, or **invite** the user (Settings →
Team → Invitations). Confirm the email's domain matches a verified/allowed domain.

### Azure `AADSTS50011` (redirect URI mismatch)

The reply URI in Azure doesn't exactly match what the UI sends. Register the
exact `FRONTEND/auth/sso/callback/entra_id` (Path B) or `FRONTEND/auth/callback`
(Path A), including scheme, host, port, and path.

### "email is registered with a different login method / identity provider"

The account is bound to another auth provider or Entra directory (issuer). This
is the account-takeover guard, not a bug — the email already has a different,
verified identity binding.

---

## 8. Working example (docker-compose env)

Placeholder values — replace with your own. `APP_ENCRYPTION_KEY` is **required in
production**: it encrypts stored client secrets and the PKCE verifier carried in
the SSO `state`. Generate one with `openssl rand -hex 32`.

```yaml
services:
  api:
    image: ghcr.io/openctemio/api:latest
    environment:
      APP_ENV: production
      # Required — encrypts per-tenant client secrets + PKCE verifier
      APP_ENCRYPTION_KEY: "b1c2...<64-hex-chars>..."   # openssl rand -hex 32

      # Frontend origins the SSO/OAuth callback may return to
      OAUTH_FRONTEND_CALLBACK_URL: "https://app.example.com/auth/callback"
      SSO_ALLOWED_REDIRECT_URIS: "https://app.example.com/auth/sso/callback/entra_id"

      # ---- Path A: "Sign in with Microsoft" (optional) ----
      OAUTH_ENABLED: "true"
      OAUTH_MICROSOFT_ENABLED: "true"
      OAUTH_MICROSOFT_CLIENT_ID: "00000000-0000-0000-0000-000000000000"
      OAUTH_MICROSOFT_CLIENT_SECRET: "<client-secret-value>"

      # ---- Path B: platform env fallback (optional; per-tenant admin UI preferred) ----
      SSO_ENTRA_ENABLED: "true"
      SSO_ENTRA_CLIENT_ID: "11111111-1111-1111-1111-111111111111"
      SSO_ENTRA_CLIENT_SECRET: "<client-secret-value>"
      SSO_ENTRA_TENANT_ID: "22222222-2222-2222-2222-222222222222"  # your directory GUID
      SSO_ENTRA_ALLOWED_DOMAINS: "example.com"
      SSO_ENTRA_DEFAULT_ROLE: "member"
      SSO_ENTRA_AUTO_PROVISION: "true"
      SSO_ENTRA_DISPLAY_NAME: "Company SSO"
      SSO_ENTRA_ALLOWED_TENANTS: "acme"        # P0 opt-in: tenant slug(s) allowed to use this fallback

      # In production, disable open registration — add users via invitations
      AUTH_ALLOW_REGISTRATION: "false"
```

For per-tenant setup (recommended), leave the `SSO_ENTRA_*` block out and have
each customer's admin add the provider under **Settings → Identity Providers**.

---

## Reference

- Architecture / rationale: [`architecture/sso-authentication.md`](../architecture/sso-authentication.md)
- SAML / SCIM (enterprise, separate): [`architecture/saml-sso.md`](../architecture/saml-sso.md),
  [`architecture/scim-provisioning.md`](../architecture/scim-provisioning.md)
- Code: `internal/app/auth/{sso.go,oauth.go,oidc_verifier.go}`,
  `internal/app/auth/domainverify/service.go`, `internal/config/config.go`,
  `internal/infra/http/routes/auth.go`
</content>
</invoke>
