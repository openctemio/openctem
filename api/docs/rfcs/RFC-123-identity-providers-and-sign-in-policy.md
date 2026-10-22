# RFC-123: Identity provider catalogue and sign-in policy

| | |
|---|---|
| Status | Accepted (2026-10-22). P0 (security debt and foundations) in review, see §6; P1 and P2 designed |
| Scope | api (`internal/app/auth`, `pkg/oidc`, `internal/app/tenant`, `internal/app/scim`, `internal/app/entitlement`, controllers), web (organization sign-in settings, console SSO pages) |
| Architecture | [sso-authentication.md](../architecture/sso-authentication.md), [saml-sso.md](../architecture/saml-sso.md), [user-two-factor-authentication.md](../architecture/user-two-factor-authentication.md), [scim-provisioning.md](../architecture/scim-provisioning.md), [limits.md](../architecture/limits.md) |
| Related | RFC-009 (SAML and SCIM), RFC-022 (platform console), RFC-024 (user two-factor), RFC-058 (external members), RFC-078 (passkeys), RFC-095 (invitations), RFC-104 (sign-up and domain policies) |

## 1. Summary

The sign-in flows are already strict: directory and hosted-domain pinning,
nOAuth protection, DNS-verified domains as the trust gate for just-in-time
accounts and SCIM, (issuer, subject) identity binding, identity-provider MFA
evidence, owner approval of console-made SSO changes, time-boxed SSO
exceptions and OIDC back-channel logout. This RFC covers three gaps:

1. **Coverage.** Per-organization OIDC is limited to three providers. There is
   no generic OIDC connector, no GitHub Enterprise sign-in and no LDAP.
2. **Operability.** Owners get no catalogue of configured and available
   connections, no test sign-in and no health view. A SAML connection holds one
   certificate, and nothing tracks when it expires.
3. **Policy and lifecycle.** The sign-in switches are spread over several
   pages. There is no "SSO must prove MFA" switch, no per-organization session
   lifetime and no replay cache for SAML assertions. Group-to-role links exist
   only for SCIM.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | One catalogue of connections per organization over the existing stores (`identity_providers`, `saml_providers`, `scim_tokens`). Who may configure it is an instance setting, `ORG_SSO_MANAGED_BY = platform_admin \| org_owner`: self-managed defaults to `platform_admin` (today's behaviour), the hosted service defaults to `org_owner`. Console changes keep the pending-owner-approval flow. An owner's own changes apply directly, with step-up, an email to every owner and a Critical audit entry. At most 3 active connections per organization. |
| D2 | A generic per-organization OIDC connector with discovery and a strict profile (§4.1). Every OIDC vendor is a preset of it (data: name, logo, scopes, group claim, issuer rule, setup hints). |
| D3 | GitLab sign-in is an OIDC preset (gitlab.com or a self-managed URL); its `groups_direct` claim feeds group links. |
| D4 | GitHub Enterprise sign-in is a small OAuth 2.0 adapter: base URL, client id and secret, a **required** organization allow-list, optional teams for group links. The identity key is (host, numeric user id). The email is the primary verified email. |
| D5 | LDAP only for self-managed Enterprise, built only on real demand. The free path is a directory federated by an OIDC provider (for example Keycloak or Authentik) through D2. |
| D6 | IdP-initiated SAML stays refused. The IdP app tile points at the SP-initiated login URL, so every response has an `InResponseTo`. |
| D7 | SAML hardening: (a) assertion-ID replay cache, fail-closed; (b) a signed assertion, exactly one, no SHA-1; (c) current and next certificate for rollover; (d) optional metadata URL refreshed daily through the SSRF-guarded client; (e) certificate expiry alerts at 30, 7 and 1 day(s). |
| D8 | IdP group links for OIDC and SAML, sharing one model with SCIM groups. Viewer and member map freely. Admin maps only through a link an owner configured. Owner is never granted by an IdP. A missing or overage group claim means "unknown", which never demotes anyone. |
| D9 | MFA policy per organization: the roles that must use 2FA, a grace period, accepted factors, and **"SSO must prove MFA"**: a session from the organization's own IdP passes only with `amr=mfa` or a multi-factor SAML context. |
| D10 | Organization idle timeout and maximum session length, each at most the platform ceiling, enforced at token mint and refresh for that organization. |
| D11 | Password and SSO switches on one page. Requiring SSO needs a verified domain and a test sign-in passed in the last 24 h. A domain that later fails re-verification alerts the owners and **keeps** enforcement. Up to 3 named break-glass owners. Password reset off for managed accounts. Auto-redirect when exactly one connection is active, with `?local=1` to bypass. |
| D12 | Passkeys for organization users (RFC-078). |
| D13 | SCIM tokens expire (1–365 days) and rotate with a short overlap. |
| D14 | A test sign-in (dry run) and a health panel per connection. A dry-run state can never create an account, a membership or a session. |
| D15 | An instance "Sign-in" page in the console: password sign-in on or off, social providers moved from environment variables to encrypted console settings, MFA for everyone, session ceilings. |
| D16 | Edition gating: security controls (MFA, passkeys, session policy, audit, break-glass) are free everywhere. On the hosted service, per-organization connections, SSO enforcement, SCIM and group links belong to the Enterprise plan. Self-managed Community keeps everything it has; LDAP is the only new Enterprise-only item. |

## 3. Threat model (summary)

Assets: memberships and roles, sessions, the IdP trust configuration, SCIM
tokens and user credentials. Actors: outside attacker, malicious member,
malicious platform administrator, compromised customer IdP and another tenant.

| # | Threat | Control |
|---|---|---|
| T1 | Cross-tenant sign-in | identity scoped to the organization; a session counts as SSO only for its issuing organization |
| T2 | IdP swap by a platform administrator | console changes wait for an owner; Critical audit; owner email |
| T3 | Rogue owner claims foreign users | JIT and attach only on the organization's verified domains |
| T4 | Mutable email (nOAuth) | identity = (issuer, subject); email trusted only when verified and on a verified domain |
| T5 | Token substitution | `aud`/`azp`, nonce, PKCE |
| T6 | Algorithm confusion | RS256, PS256, ES256 only |
| T7 | Issuer mix-up | exact issuer; the state carries the connection |
| T8 | SSRF through issuer or metadata URLs | URL guard, no private ranges on the hosted service |
| T9 | SAML replay | `InResponseTo` + single-use cookie + assertion-ID cache, fail-closed |
| T10 | XML signature wrapping | one assertion, its own signature required, regression corpus |
| T11 | IdP-initiated login CSRF | unsolicited responses refused |
| T12 | Weak crypto | SHA-1 refused |
| T13 | Privilege escalation through IdP groups | owner never; admin only through an owner-configured link |
| T14 | Silent demotion | unknown is not empty; only IdP-sourced roles change |
| T15 | Lock-out by enforcement | owners and named break-glass are exempt; enforcement needs a test pass; certificate expiry alerts |
| T16 | Enforcement bypass | enforced at the mint gate for every method; reset off for managed accounts |
| T17 | MFA bypass through federation | "SSO must prove MFA" |
| T18 | SCIM token theft | expiry, rotation, prefix for secret scanning |
| T19 | Deprovision gap | SCIM suspend, back-channel logout, maximum session length |
| T20 | Dry run turned into a login | the dry-run state never reaches account or session code |
| T21 | Secret disclosure | write-only secrets, redaction |
| T22 | GitHub organization bypass | required organization allow-list |
| T23 | LDAP pitfalls | empty-password refusal, RFC 4515 escaping, TLS required |
| T24 | DNS-loss downgrade | re-verification failure alerts but keeps enforcement |
| T25 | Brute force and enumeration | rate limits, uniform errors |

Authorization: organization writes need the owner with step-up, reads need
an administrator, console routes keep their gates and the pending approval,
every query is scoped by the session's tenant, and a foreign id answers 404.

## 4. Design notes

### 4.1 Generic OIDC profile

Discovery through the SSRF-guarded client with a byte-exact issuer match.
Authorization code + PKCE S256 + nonce + signed state, no implicit or hybrid
flow. A verified id_token is required (RS256/PS256/ES256, `aud`, `azp` with
several audiences, 2-minute skew, `auth_time` when re-authentication was
asked for). Identity is (`iss`, `sub`) scoped to the organization. Email
finds or creates an account only when it is verified and on a verified
domain. Userinfo is used only for the display name and groups.

### 4.2 Plan features

The named features are `sso.connections`, `sso.enforcement`, `scim`,
`sso.group_links` and `ldap`. A downgrade never locks anyone out: sign-in
through configured connections keeps working, and enforcement is switched off
after the read-only grace. [limits.md](../architecture/limits.md) lists the
seams.

## 5. Plan

| Phase | Items |
|---|---|
| P0 | SCIM token expiry and rotation (D13); SAML replay cache, signed assertion, no SHA-1, certificate expiry (D7 a, b, e); "SSO must prove MFA" (D9, part); verified-domain precondition and DNS-loss rule (D11, part); identity-token algorithm allow-list and verified id_token everywhere (§4.1); plan features (D16) |
| P1 | generic OIDC connector and presets (D2, D3); test sign-in and health (D14); catalogue and connection UI (D1); `ORG_SSO_MANAGED_BY` and owner self-service (D1); group links (D8); sign-in and MFA policy page with session policy (D9–D11); passkeys (D12) |
| P2 | GitHub Enterprise adapter (D4); SAML metadata URL and certificate rollover (D7 c, d); console "Sign-in" page and social providers in the console (D15); `private_key_jwt` client authentication; LDAP on demand (D5) |

## 6. Implementation

| Item | Pull request | State |
|---|---|---|
| SCIM token expiry and rotation | #2789 | in review |
| SAML replay cache, signed assertion, no SHA-1, certificate expiry alerts | #2785 | in review |
| "SSO must prove two-factor" | #2788 | in review |
| Requiring SSO needs a verified domain; DNS loss keeps enforcement | #2793 | in review |
| id_token algorithm allow-list; Google sign-in requires a verified id_token | #2794 | in review |
| Plan features for SSO, SCIM and group links | #2797 | in review |
