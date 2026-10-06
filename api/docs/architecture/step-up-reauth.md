# Step-up re-authentication

A signed-in session is enough for everyday work. A few actions can hand an
attacker the organization if the session is stolen (a copied cookie, an
unlocked laptop): minting a long-lived credential, changing who can sign in,
deleting the organization, removing a person and their data. For those the API
asks the user to prove their identity again, recently, in the same session.

Source: settings research P1-01 and owner decision B7 (window 10 minutes,
password or TOTP; SSO users re-authenticate at their identity provider).

## Model

- **Recent authentication** of a session = the later of its sign-in
  (`sessions.created_at`) and its last successful step-up
  (`sessions.step_up_at`, migration `001116`).
- A session created by the **organization's identity provider** (OIDC SSO or
  SAML: `auth_method` `sso`/`saml` with `idp_tenant_id`) does not count its
  creation. Its recent authentication is the provider's own: the id_token
  `auth_time` or the SAML `AuthnInstant`, stamped as `step_up_at` at sign-in
  when it is within the window. A provider that signs the user in silently
  from a session it remembers therefore opens no window. A global social
  sign-in (no `idp_tenant_id`) counts its creation, like a password.
- A sensitive route accepts the request while recent authentication is less
  than **10 minutes** old (`authapp.StepUpWindow`). The window is fixed from
  the moment of proof; using it does not extend it.
- The state lives on the server, on one session row. It is not a token claim
  or a client flag, so it cannot be replayed from another browser, another
  session of the same user, or by another user naming the session id.

## API

| Route | What it does |
|---|---|
| `GET /api/v1/auth/step-up` | `{method, valid_until?, window_seconds}`. `method` is `totp` (the account has an authenticator), `password` (local account without one) or `fresh_sign_in` (SSO account without an authenticator). |
| `POST /api/v1/auth/step-up` | Body `{"totp": "123456"}` or `{"password": "…"}`. On success stamps `step_up_at = now` on the calling session and returns `{valid_until, window_seconds}`. |

Proof rules (`AuthService.VerifyStepUp`, shared with sensor-pairing approval):

- An account with TOTP must give a current code. A password is not accepted,
  a recovery code is not accepted, and a code from an already used time step is
  refused (the same compare-and-set replay guard as sign-in).
- A local account without TOTP gives its password.
- An SSO account without TOTP has nothing the API can verify: the call answers
  `403 STEP_UP_UNAVAILABLE` and the user signs in again at the identity
  provider. This path never stamps the session, so a session cannot push its
  own window forward without a proof.

## Re-authentication at the identity provider

The web dialog's "Sign in again" ends the session and opens
`/login?org=<organization>&reauth=1`. The sign-in then asks the provider to
authenticate the user again:

| Protocol | Request | Checked on the way back |
|---|---|---|
| OIDC (`GET /api/v1/auth/sso/{provider}/authorize?…&reauth=true`) | `prompt=login` and `max_age=0` (Google: `max_age=0` with its own `prompt`); the flag rides in the signed `state` | the id_token must carry `auth_time` no older than 5 minutes (2 minutes of skew); otherwise the sign-in is refused |
| SAML (`GET /api/v1/auth/saml/{org}/login?reauth=1`) | `ForceAuthn="true"` in the AuthnRequest; the request-tracking cookie remembers it | the signed assertion's `AuthnInstant` must be no older than 5 minutes; otherwise the sign-in is refused |

The window itself never depends on the flag: it opens only from the
provider's signed authentication time (see Model). Entra ID includes
`auth_time` only when the app registration adds it as an optional claim
(`docs/how-to/configure-entraid.md`).

Errors:

| Status / code | When |
|---|---|
| `400` | No proof of the kind the account needs. |
| `403 STEP_UP_FAILED` | Wrong or replayed code, wrong password. Audited (`auth.step_up_failed`, high). Counts towards the account lockout. |
| `403` "Account is locked…" | The lockout from repeated failures (sign-in and step-up share the counter). |
| `403 STEP_UP_UNAVAILABLE` | SSO-only account, or the session is not an active session of the caller. |
| `429` | Per-IP bucket `step-up` (5/min, shared store across replicas). |

Success is audited as `auth.step_up` (medium) with the method and the window end.

## Protecting a route

```go
r.POST("/", h.Create, middleware.Require(permission.APIKeysWrite), requireStepUp())
```

`requireStepUp()` (routes package) wraps `middleware.RequireRecentAuth(checker,
authapp.StepUpWindow)`. Mount it **after** the permission check, so a caller
without the permission is told so before being asked to re-authenticate. It
answers:

- `403 STEP_UP_REQUIRED` (`details.window_seconds`): the session is outside its
  window, or unknown, revoked, expired or another user's.
- `403 STEP_UP_UNAVAILABLE`: the request has no user session that can step up
  (an `oct_` API key, a token without a session id), or no checker is wired.

A token from the external OIDC provider (`AUTH_PROVIDER=oidc`/`hybrid`) has no
platform session. Its recent authentication is the provider's signed
`auth_time` claim: the route admits it while `auth_time` is within the window,
answers `STEP_UP_REQUIRED` when it is older (the client signs in at the
provider again with `prompt=login` / `max_age=0` and sends the new token), and
`STEP_UP_UNAVAILABLE` when the token has no `auth_time`. A refreshed token
keeps its original `auth_time`, so refreshing never extends the window.
- `500`: the lookup failed. It fails closed.

Add every new protected route to `stepUpRoutes` in
`internal/infra/http/routes/step_up_routes_test.go`; the test proves each one
refuses outside the window and passes inside it.

## Protected routes

| Route | Why |
|---|---|
| `POST /api/v1/api-keys`, `DELETE /api/v1/api-keys/{id}` | A new key outlives the session; deleting one hides it. Revoking stays one click. |
| `POST /api/v1/scim-tokens` | A SCIM token creates, suspends and re-roles every member. |
| `PATCH /api/v1/tenants/{tenant}/settings/security` | MFA requirement, IP allowlist, allowed domains, SSO enforcement. |
| `POST /api/v1/tenants/{tenant}/settings/sso/changes/{id}/approve` | Installs who can sign in to the organization. |
| `DELETE /api/v1/tenants/{tenant}` | Deletes the organization. |
| `DELETE /api/v1/organization/members/{id}/mfa` | Removes a member's second factor. |
| `POST /api/v1/organization/members/{id}/offboard`, `.../erase` | Removes a person's access; erases their personal data. |
| `POST /api/v1/ci/gate-overrides` | Break-glass past the CI security gate. |
| `POST /api/v1/audit-logs/rebaseline` | Overwrites the tamper-evident audit chain. |

Sensor pairing approval (`POST /api/v1/sensor-pairings/{id}/approve`, RFC-052)
checks a step-up proof inside the request body with the same
`VerifyStepUp`. Reads and cosmetic changes never prompt.

The platform admin console has its own sessions: it already requires a fresh
authenticator code inside the request for the audit-chain rebaseline
(`console.step_up`); see `authorization-matrix.md` › Platform Admin Routes.

## Web

The API client turns `STEP_UP_REQUIRED` into one shared re-authentication
dialog (authenticator code or password; "sign in again" for SSO-only accounts),
calls `POST /auth/step-up`, and retries the original request once.

## Threat model

- **Asset:** organization configuration, credentials and data.
- **Actor:** someone holding a stolen session (cookie or bearer token) or a
  borrowed unlocked browser.
- **Blocked:** minting a persistent API or SCIM credential, opening the IP
  allowlist or turning MFA off, approving a hostile SSO change, deleting the
  organization, offboarding or erasing members, overriding the CI gate,
  rebaselining the audit chain — unless the attacker also has the password or
  the authenticator, or uses the session within 10 minutes of the victim's
  own sign-in or step-up.
- **Guessing:** wrong proofs count towards the account lockout and the per-IP
  bucket; TOTP codes are single use.
- **Cross-session / cross-user:** the stamp is keyed by session id and user id;
  a step-up in one session opens nothing in another, and a token naming
  another user's session is refused.
- **Silent federated sign-in:** an attacker at an unlocked browser whose
  identity provider session is still alive can sign in again without a
  password, but that session opens no window: only a recent, signed provider
  authentication (`auth_time`, `AuthnInstant`) does, and the re-sign-in asks
  the provider for one (`prompt=login`, `max_age=0`, `ForceAuthn`).
- **Residual:** a stolen session used inside the victim's own window; a
  provider that ignores `prompt=login` yet reports a fresh `auth_time` is
  trusted (its signature is what we verify); a global social sign-in (Google,
  GitHub, Microsoft without an organization IdP) counts from its creation.

## Key files

- `internal/app/auth/stepup.go` (proof), `internal/app/auth/stepup_session.go` (window)
- `internal/infra/http/middleware/step_up.go` (`RequireRecentAuth`)
- `internal/infra/http/handler/local_auth_stepup_handler.go`
- `internal/infra/postgres/session_repository.go` (`MarkStepUp`, `RecentAuthAt`)
- `internal/infra/http/routes/step_up_routes_test.go`, `step_up_db_test.go`
