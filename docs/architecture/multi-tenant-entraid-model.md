# One Platform, Many Tenants — Each Brings Its Own EntraID

> **The model in one line:** every customer org registers **its own Azure AD app in its own Azure directory**; OpenCTEM stores one SSO config per tenant and, at login, routes each user to **their tenant's** Azure directory — never a shared one. The Azure `tid` (directory id) is pinned per tenant, so one tenant's login can never accept another tenant's token.

This document explains *how* multi-tenant EntraID works conceptually. For the step-by-step operator setup (Azure app registration, env vars, admin UI), see the how-to: [Configure Microsoft Entra ID SSO](../how-to/configure-entraid.md). For the security design (id_token verification, nOAuth/`xms_edov`, PKCE, verified-domain JIT), see [SSO Authentication](sso-authentication.md).

---

## Two levels of "tenant" — don't conflate them

There are two different directories in play, and the whole model hinges on keeping them straight:

| | **OpenCTEM tenant** | **Azure AD tenant (directory)** |
|---|---|---|
| What it is | A customer org inside OpenCTEM (`org=acme`) | The customer's Microsoft Entra directory (`tid = A1b2…`) |
| Who owns it | The platform (us) | The customer's IT |
| Identified by | tenant slug / id | Azure `tid` (a GUID) |

A per-tenant Entra connection **binds one OpenCTEM tenant to one Azure directory**. Acme's OpenCTEM tenant ⇄ Acme's Azure directory; Globex's ⇄ Globex's. They never cross.

---

## 1. Setup — each tenant = its own Azure app + directory

A tenant admin registers the org's Azure app in the Azure Portal, then enters its credentials into OpenCTEM (Settings → Identity Providers, or the `SSO_ENTRA_*` env fallback). Different tenant → different `client_id` / `client_secret` / directory `tid`.

```
Acme Corp    (org=acme)   →  Azure dir tid=A1b2…  ·  client_id acme-…    ·  secret 🔒  ·  @acme.com  (verified)
Globex Ltd   (org=globex) →  Azure dir tid=9x8y…  ·  client_id globex-…  ·  secret 🔒  ·  @globex.io (verified)
Initech      (org=initech)→  no Entra configured  →  email + password only
```

Stored as one row per tenant in **`tenant_identity_providers`** (tenant-scoped; the client secret is AES-256-GCM encrypted at rest):

```jsonc
{ tenant_id: "acme",   provider: "entra_id", client_id: "acme-…",   tid: "A1b2…", secret: 🔒enc }
{ tenant_id: "globex", provider: "entra_id", client_id: "globex-…", tid: "9x8y…", secret: 🔒enc }
// initech: no row → falls back to local login
```

---

## 2. Login — how a request reaches the *right* tenant's Azure

The app cannot guess which tenant a user belongs to. The user enters through a **tenant-specific entry point**: `/login?org=<slug>`. That slug — carried inside an **HMAC-signed OAuth `state`** — selects which tenant's config to use, both when redirecting to Azure and when completing the callback.

```
① AUTHORIZE  (before auth)                     ② CALLBACK  (after auth)
/login?org=acme                                /auth/sso/callback/entra_id?code&state
   │ slug = acme                                   │ recover slug FROM the signed state
   ▼                                                ▼
GetBySlug("acme") → tenant                       validateState → slug → GetBySlug → tenant
   │                                                │
tenant_identity_providers[acme]                  verify id_token:
   → client_id, tid, authorize endpoint             · signature (Azure JWKS)
   → build authorize URL for ACME's Azure app       · nonce
   ▼                                                 · iss ⊃ tid  AND  tid == acme's pinned tid   ◄── the wall
login.microsoftonline.com/A1b2…/oauth2/…            │  reject if the token is from any other directory
   (Acme employee signs into ACME's directory)   membership(user, acme)?  → issue an ACME session
```

Step by step for an **Acme** employee:

1. **User opens Acme's login** — `/login?org=acme`. The slug `acme` is the tenant context (a routing hint, signed into `state`).
2. **App looks up Acme's config** — `GetBySlug("acme")` → the `tenant_identity_providers` row → build the authorize URL against **Acme's Azure directory + Acme's client_id**.
3. **Redirect to Acme's Azure AD** — `login.microsoftonline.com/A1b2…/…`. The Acme employee signs in against **Acme's own directory** (their users, their MFA). Globex's directory is never involved.
4. **Callback — verify the token is really Acme's** — recover `org=acme` from the signed state; verify the id_token signature + nonce, and **pin `tid` = Acme's directory**.
5. **Identity + membership → Acme session** — key the user by immutable `oid+tid` (never the mutable email), confirm they're a member of Acme (or JIT-provision if their email is on Acme's DNS-**verified domain**), and issue a tenant-scoped session.

Globex runs the exact same flow in parallel, fully isolated: `org=globex` → Globex's app → `…/9x8y…` → `tid` must equal `9x8y…` → a Globex session.

---

## 3. Why they can't mix — the `tid`-pin is the wall

**The org-slug only *picks the config*; the `tid`-pin + membership *enforce who gets in*.**

Acme's login only accepts a token whose Azure directory id equals **Acme's configured `tid`**. So:

- A **Globex** user who tries Acme's `?org=acme` entry authenticates against *Globex's* directory → the returned token carries `tid = 9x8y…` ≠ Acme's `A1b2…` → **rejected**.
- An **attacker with their own Azure tenant** who sets their email to a victim's address (the *nOAuth* class) is stopped twice: the token's `tid` isn't Acme's, **and** identity is keyed on immutable `oid+tid` with email trusted only when `xms_edov=true` — never on a mutable email claim.

The signed `state` is likewise a routing hint, not a trust boundary: knowing another tenant's slug gets you nothing, because you still have to produce a token from *that tenant's pinned directory* and pass its membership check.

> Multi-tenant Azure "`/common`" authorities (which accept *any* directory) are only safe when the `tid` is pinned. A per-tenant connection pins a specific directory GUID, so isolation is a property of the configuration, not of remembering to validate in code.

---

## Edge cases

- **A user belongs to multiple tenants** — each tenant has its own `?org=<slug>` entry; whichever slug is in the state wins. There is no cross-tenant "pick an org" step for SSO (the app resolves exactly the tenant in the state).
- **A user belongs to no tenant yet** — if the provider allows JIT and the user's email is on a verified domain of that tenant, a membership is provisioned on the fly; otherwise they get a session with no tenant access (invite-only). See the [verified-domain JIT gate](sso-authentication.md).
- **A tenant with no Entra configured** (Initech) — simply has no `tenant_identity_providers` row and uses local email/password login.

---

## The three ways Entra can be wired

| Mode | What it is | When |
|---|---|---|
| **Per-tenant** ⭐ (this doc) | Each tenant's own Azure app in `tenant_identity_providers`, org-scoped via `?org=`, `tid`-pinned | The recommended, isolated model — one customer per connection |
| **Global "Sign in with Microsoft"** | One platform-wide social button (`OAUTH_MICROSOFT_*`, `/common`), not tenant-bound → lands on onboarding | A convenience social login, not org SSO |
| **Env fallback (opt-in)** | A shared Azure app (`SSO_ENTRA_*`) for tenants that explicitly opt in (`SSO_ENTRA_ALLOWED_TENANTS`); fail-closed defaults | Only for tenants without their own app; guarded so it can't become an open self-join |

---

## Code map

| Concern | Where |
|---|---|
| Per-tenant config storage | `tenant_identity_providers` table · `pkg/domain/identityprovider` |
| Resolve config for a login | `internal/app/auth/sso.go` — `resolveProvider`, `GetProvidersForTenant`; tenant via `GetBySlug(orgSlug)` |
| Build authorize URL + signed state | `sso.go` — `GenerateAuthorizeURL`, `generateState` (HMAC + `?org` + nonce) |
| id_token verification + **`tid` pin** | `internal/app/auth/oidc_verifier.go` — `entraIssuerValidator` (pins the directory when a GUID is configured) |
| Immutable-id keying + `xms_edov` | `sso.go` — `entraUserInfoFromClaims` (email trusted only with `xms_edov`; keys on `oid`/`sub`+`iss`) |
| Verified-domain JIT gate | `internal/app/auth/domainverify/` · `sso.go` — `jitProvisioningAllowed` |
| Env-fallback opt-in | `sso.go` — `envProvider`, `envFallbackAllowedForTenant` (`SSO_ENTRA_ALLOWED_TENANTS`) |

**See also:** [SSO Authentication (design)](sso-authentication.md) · [Configure EntraID (how-to)](../how-to/configure-entraid.md) · [SAML SSO](saml-sso.md).
