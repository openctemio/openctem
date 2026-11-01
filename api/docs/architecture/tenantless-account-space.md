# Account space for a person with no organization

Design: [RFC-141](../rfcs/RFC-141-tenantless-account-space.md).

## States

| Session | Token | Reaches |
|---|---|---|
| In an organization | Access token with `tenant`, `role`, permissions | Every route its permissions allow |
| Account only | Access token without `tenant` | The account allow-list only |
| Signed out / refused sign-up | None | Public routes |

## Getting an account-only token

`POST /api/v1/auth/account-token` with the refresh token (httpOnly cookie plus the CSRF pair, or
`refresh_token` in the body). It answers:

- `200 {access_token, token_type, expires_in}` and a rotated refresh cookie, when the account has
  no organization it can open (none, or every one suspended or closed);
- `409` when the account can open an organization: exchange with `POST /auth/token` instead;
- `401` for a refresh token that is unknown, spent (the family is revoked), expired, or for a
  blocked account.

Social and SSO sign-in return a token without a tenant at sign-in; the allow-list applies to it the
same way.

## The allow-list

`internal/infra/http/middleware/tenantless.go` lists every route an account-only token may call,
as `METHOD /path` with `{name}` for one segment. `UnifiedAuth` refuses any other route with
`401 TENANT_REQUIRED` before the handler runs. 401 keeps the web client's behaviour for a member's
social sign-in token (it exchanges on 401); the code tells an account-only client that exchanging
will not help.

To add a route: it must hold no tenant data and act only on the caller's own account. Add it to the
list in the same pull request; `routes/tenantless_allowlist_test.go` fails until the list and the
router agree.

## Invitations

| Route | Auth | Notes |
|---|---|---|
| `POST /auth/onboarding/options` | refresh token | Invitations for the verified address only; references are HMAC-bound to the account and expire |
| `POST /auth/onboarding/accept` | refresh token | Re-checks the reference, verified address, pending state, the organization's policies; audited `invitation.accepted` |
| `POST /auth/onboarding/decline` | refresh token | Invitation references only; verified address; pending; deletes the invitation; audited `invitation.deleted` with `declined: true` |

## Creating an organization

`POST /tenants` is on the allow-list, so the creation policy is the only gate, and it is enforced in
the handler: an organization is created only when the sign-up policy admits an organization
(`SIGNUP_MODE=open` ceiling and a console policy of `self_service`, and the person's email domain
does not block new organizations). The defaults:

| Installation | `SIGNUP_MODE` | Console policy | Person may create |
|---|---|---|---|
| Self-hosted (default) | `disabled` | `admin_only` | No: only a platform administrator creates organizations |
| Self-hosted with domain sign-up | `domain` | `admin_only` | No |
| Hosted self-service | `open` | `self_service` | Yes, unless the domain blocks it |

A policy that cannot be read is `admin_only`. `/auth/onboarding/options` reports the answer for the
signed-in person as `can_create_organization`; the web hub shows "Create an organization" only when
it is true, and says to ask an administrator otherwise. A test sends `POST /tenants` with an
account-only token under each self-hosted setting and expects 403.

## Web

- Sign-in with no organization calls `POST /auth/account-token` and lands on `/welcome`. The web
  keeps an `app_account_only` cookie as a routing hint (the API trusts only the token).
- `/welcome` lists invitations (accept, decline), the organization of a verified domain, "Create an
  organization" when allowed, and links to profile, security, sessions, sign-in methods and
  preferences.
- The proxy sends every page of an account-only session except `/welcome`, `/account`,
  `/account/security` and `/account/preferences` to `/welcome`. Those pages render in a slim shell
  with no tenant providers.
- The browser's refresh renews the account-only token while no organization cookie exists.
- The API client routes `401 TENANT_REQUIRED` to `/welcome` once.

## What does not change

Step-up for sensitive account changes (password change needs the current password, two-factor off
needs password and code, account deletion needs step-up, sign-in method changes need a proof typed
for the request), CSRF for cookie sessions, rate limits, session lifetimes and sign-out.
# Account space for a person with no organization

Design: [RFC-141](../rfcs/RFC-141-tenantless-account-space.md).

## States

| Session | Token | Reaches |
|---|---|---|
| In an organization | Access token with `tenant`, `role`, permissions | Every route its permissions allow |
| Account only | Access token without `tenant` | The account allow-list only |
| Signed out / refused sign-up | None | Public routes |

## Getting an account-only token

`POST /api/v1/auth/account-token` with the refresh token (httpOnly cookie plus the CSRF pair, or
`refresh_token` in the body). It answers:

- `200 {access_token, token_type, expires_in}` and a rotated refresh cookie, when the account has
  no organization it can open (none, or every one suspended or closed);
- `409` when the account can open an organization: exchange with `POST /auth/token` instead;
- `401` for a refresh token that is unknown, spent (the family is revoked), expired, or for a
  blocked account.

Social and SSO sign-in return a token without a tenant at sign-in; the allow-list applies to it the
same way.

## The allow-list

`internal/infra/http/middleware/tenantless.go` lists every route an account-only token may call,
as `METHOD /path` with `{name}` for one segment. `UnifiedAuth` refuses any other route with
`401 TENANT_REQUIRED` before the handler runs. 401 keeps the web client's behaviour for a member's
social sign-in token (it exchanges on 401); the code tells an account-only client that exchanging
will not help.

To add a route: it must hold no tenant data and act only on the caller's own account. Add it to the
list in the same pull request; `routes/tenantless_allowlist_test.go` fails until the list and the
router agree.

## Invitations

| Route | Auth | Notes |
|---|---|---|
| `POST /auth/onboarding/options` | refresh token | Invitations for the verified address only; references are HMAC-bound to the account and expire |
| `POST /auth/onboarding/accept` | refresh token | Re-checks the reference, verified address, pending state, the organization's policies; audited `invitation.accepted` |
| `POST /auth/onboarding/decline` | refresh token | Invitation references only; verified address; pending; deletes the invitation; audited `invitation.deleted` with `declined: true` |

## What does not change

Step-up for sensitive account changes (password change needs the current password, two-factor off
needs password and code, account deletion needs step-up, sign-in method changes need a proof typed
for the request), CSRF for cookie sessions, rate limits, session lifetimes and sign-out.
