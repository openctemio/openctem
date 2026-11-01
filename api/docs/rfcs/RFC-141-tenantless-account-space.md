# RFC-141: Account space for a person with no organization

| | |
|---|---|
| Status | Accepted (2026-11-01). Implemented: the account allow-list for tokens without a tenant, enforced in the auth middleware with a test over every user-plane route; `POST /auth/account-token`; `POST /auth/onboarding/decline`; the `TENANT_REQUIRED` error code. Web: the account space (`/welcome`, the slim account shell for profile, security and preferences, the proxy redirect, `TENANT_REQUIRED` handling) |
| Scope | api, web |
| Related | RFC-024 (user two-factor), RFC-095 (invitations), RFC-104 (sign-up modes and joining), RFC-134 (platform administration) |

## 1. Summary

A person can hold an account and belong to no organization: invited before accepting, removed
from their last organization, the organization deleted or suspended, or signed up on the hosted
service without a team yet. Such a person must be able to manage their own account (profile,
password, two-factor, sessions, sign-in methods, preferences), see and answer invitations sent to
their verified address, and create an organization where the policy allows it. They must reach
nothing else.

## 2. Design

- **Token.** `POST /auth/account-token` (refresh-token authenticated, cookie + CSRF or body) mints
  an access token with no tenant claim, for an account with no organization it can open. An
  account that can open an organization gets 409 and exchanges its token for that organization
  (every organization sign-in policy still applies). The refresh token is checked as for an
  exchange and rotated in its family. Social and SSO sign-in already return a token without a
  tenant; the same rules apply to it.
- **Deny by default.** The auth middleware refuses a token without a tenant on every route outside
  an explicit allow-list of method and path patterns (`internal/infra/http/middleware/tenantless.go`)
  with `401 TENANT_REQUIRED`, before any handler. Paths not in canonical form never match. A
  route test parses every registered user-plane route and checks that the list and the router
  agree and that each other route refuses such a token while an organization token passes.
- **Allow-list.** Profile and preferences; own memberships, creating an organization (the handler
  applies the creation policy), module presets; password, sessions, two-factor; sign-in methods;
  account deletion; accepting an invitation by its token; step-up and sign-out; version and
  announcements. Notifications, API keys and MCP connections read tenant data and are not on it.
- **Invitations.** Listed by `/auth/onboarding/options` only for a verified address, each with an
  opaque reference bound to the account. Accept (`/auth/onboarding/accept`) and decline
  (`/auth/onboarding/decline`) check the reference, the verified address and that the invitation
  is still pending; both are audited in the inviting organization.
- **Web.** Sign-in with no organization stores the account-only token and lands on `/welcome`
  (invitations with accept and decline, account links, "Create an organization" only when the
  API's policy allows it for the person, sign out). `/account`, `/account/security` and
  `/account/preferences` render in a slim shell without the organization sidebar; the proxy sends
  every other page of such a session to `/welcome`, and the API client does the same on
  `401 TENANT_REQUIRED`. `/not-set-up` stays a refusal with next steps and names no organization.
- **Creating an organization.** Offered only where `can_create_organization` in the onboarding
  options is true, which is the sign-up policy (`SIGNUP_MODE` ceiling, console policy, domain
  rule). The default is `SIGNUP_MODE=disabled`, so on a self-hosted installation the hub says to
  ask an administrator, and `POST /tenants` with an account-only token answers 403.
- **Unchanged.** A refused sign-up creates no account. An SSO sign-in that maps to no organization
  creates no session. Step-up, CSRF, rate limits and session lifetimes are the same as for any
  session.

## 3. Threat model

Tenant data read with a token without a tenant (deny by default, route test); a new route that
accepts it (the test fails until it is listed on purpose); path tricks (canonical paths only); a
member skipping an organization's SSO or two-factor policy (409 for members); refresh replay
(shared checks, family revocation); invitation enumeration (verified own address only,
account-bound references, one answer for every refusal). Architecture:
`docs/architecture/tenantless-account-space.md`.
# RFC-141: Account space for a person with no organization

| | |
|---|---|
| Status | Accepted (2026-11-01). Implemented: the account allow-list for tokens without a tenant, enforced in the auth middleware with a test over every user-plane route; `POST /auth/account-token`; `POST /auth/onboarding/decline`; the `TENANT_REQUIRED` error code. Designed: the web account space (`/welcome`, the account shell for profile, security and preferences) |
| Scope | api, web |
| Related | RFC-024 (user two-factor), RFC-095 (invitations), RFC-104 (sign-up modes and joining), RFC-134 (platform administration) |

## 1. Summary

A person can hold an account and belong to no organization: invited before accepting, removed
from their last organization, the organization deleted or suspended, or signed up on the hosted
service without a team yet. Such a person must be able to manage their own account (profile,
password, two-factor, sessions, sign-in methods, preferences), see and answer invitations sent to
their verified address, and create an organization where the policy allows it. They must reach
nothing else.

## 2. Design

- **Token.** `POST /auth/account-token` (refresh-token authenticated, cookie + CSRF or body) mints
  an access token with no tenant claim, for an account with no organization it can open. An
  account that can open an organization gets 409 and exchanges its token for that organization
  (every organization sign-in policy still applies). The refresh token is checked as for an
  exchange and rotated in its family. Social and SSO sign-in already return a token without a
  tenant; the same rules apply to it.
- **Deny by default.** The auth middleware refuses a token without a tenant on every route outside
  an explicit allow-list of method and path patterns (`internal/infra/http/middleware/tenantless.go`)
  with `401 TENANT_REQUIRED`, before any handler. Paths not in canonical form never match. A
  route test parses every registered user-plane route and checks that the list and the router
  agree and that each other route refuses such a token while an organization token passes.
- **Allow-list.** Profile and preferences; own memberships, creating an organization (the handler
  applies the creation policy), module presets; password, sessions, two-factor; sign-in methods;
  account deletion; accepting an invitation by its token; step-up and sign-out; version and
  announcements. Notifications, API keys and MCP connections read tenant data and are not on it.
- **Invitations.** Listed by `/auth/onboarding/options` only for a verified address, each with an
  opaque reference bound to the account. Accept (`/auth/onboarding/accept`) and decline
  (`/auth/onboarding/decline`) check the reference, the verified address and that the invitation
  is still pending; both are audited in the inviting organization.
- **Unchanged.** A refused sign-up creates no account. An SSO sign-in that maps to no organization
  creates no session. Step-up, CSRF, rate limits and session lifetimes are the same as for any
  session.

## 3. Threat model

Tenant data read with a token without a tenant (deny by default, route test); a new route that
accepts it (the test fails until it is listed on purpose); path tricks (canonical paths only); a
member skipping an organization's SSO or two-factor policy (409 for members); refresh replay
(shared checks, family revocation); invitation enumeration (verified own address only,
account-bound references, one answer for every refusal). Architecture:
`docs/architecture/tenantless-account-space.md`.
