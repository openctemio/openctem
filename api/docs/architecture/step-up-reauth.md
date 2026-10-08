# Step-up re-authentication

A signed-in session is enough for everyday work. A few actions can hand an
attacker the organization if the session is stolen (a copied cookie, an
unlocked laptop): minting a long-lived credential, changing who can sign in,
deleting the organization, removing a person and their data. For those the API
asks the user to prove their identity again, recently, in the same session.

Decision B7 (window 10 minutes,
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
- `500`: the lookup failed. It fails closed.

A token from the external OIDC provider (`AUTH_PROVIDER=oidc`/`hybrid`) has no
platform session. Its recent authentication is the provider's signed
`auth_time` claim: the route admits it while `auth_time` is within the window,
answers `STEP_UP_REQUIRED` when it is older (the client signs in at the
provider again with `prompt=login` / `max_age=0` and sends the new token), and
`STEP_UP_UNAVAILABLE` when the token has no `auth_time`. A refreshed token
keeps its original `auth_time`, so refreshing never extends the window.

Add every new protected route to `stepUpRoutes` in
`internal/infra/http/routes/step_up_routes_test.go`; the test proves each one
refuses outside the window and passes inside it.

Step-up follows the action, not the path. `stepUpServiceActions` in
`tests/unit/step_up_service_mapping_test.go` lists the service actions that
need it; the test maps each one to every user-plane route whose handler
reaches it (directly or through a service method) and fails when one of those
routes lacks `requireStepUp()`. A second route to the same action cannot skip
step-up. Offboarding has one route, `POST /api/v1/organization/members/{id}/offboard`;
the former `DELETE /api/v1/tenants/{tenant}/members/{id}` reached the same
offboarding without step-up and is removed.

## Protected routes

| Route | Why |
|---|---|
| `POST /api/v1/api-keys`, `DELETE /api/v1/api-keys/{id}` | A new key outlives the session; deleting one hides it. Revoking stays one click. |
| `POST /api/v1/scim-tokens` | A SCIM token creates, suspends and re-roles every member. |
| `PATCH /api/v1/tenants/{tenant}/settings/security` | MFA requirement, IP allowlist, allowed domains, SSO enforcement. |
| `POST /api/v1/tenants/{tenant}/settings/sso/changes/{id}/approve` | Installs who can sign in to the organization. |
| `DELETE /api/v1/tenants/{tenant}` | Deletes the organization. |
| `DELETE /api/v1/organization/members/{id}/mfa` | Removes a member's second factor. |
| `POST /api/v1/organization/members/{id}/offboard`, `.../erase` | Removes a person's access; erases their personal data. Disabling (`POST /api/v1/tenants/{tenant}/members/{id}/suspend`) and re-enabling stay one click: they are reversible and keep everything the member holds. |
| `POST /api/v1/ci/gate-overrides` | Break-glass past the CI security gate. |
| `GET /api/v1/integrations/{jira,github}/webhook-secret`, `POST …/webhook-secret/rotate` | Whoever holds the secret can forge inbound webhook events (issue sync, repository events) for the organization. |
| `PATCH /api/v1/attachments/storage-config` | Decides where evidence files are written and with which credentials. |
| `POST /api/v1/sensors`, `POST /api/v1/sensors/{id}/regenerate-key` | Mints a persistent sensor key, a credential that outlives the session (the same reason as an API key). Revoking, disabling and deleting stay one click. |
| `POST /api/v1/credentials/{id}/reveal` | Returns a leaked credential in plaintext; also audited (`credential.revealed`), and the response is not cached. |

### Actions that need step-up only in some cases

Some routes need step-up only for one kind of change, which only the service
can tell. The service asks a `shared.RecentAuthGate` (wired at startup to
`middleware.RecentAuthGate`, which calls `middleware.CheckRecentAuth`, the
check behind `requireStepUp()`), and the handler answers its refusal with
`middleware.WriteStepUpError`, exactly like the middleware
(`403 STEP_UP_REQUIRED` with `window_seconds`, or `STEP_UP_UNAVAILABLE`), so
the web dialog appears and the request is retried.

| Action | Where it is checked |
|---|---|
| Making someone an administrator or an owner: `POST /api/v1/users/{id}/roles`, `PUT /api/v1/users/{id}/roles`, `POST /api/v1/roles/{id}/members/bulk` with the admin or owner role, `POST/PATCH /api/v1/tenants/{tenant}/members…` with `admin`, an invitation or a created user with the admin role | `RoleService.authorizeAdminPromotion`, `TenantService.authorizeAdminPromotion` (only when the user does not hold the role yet) |
| Renaming the organization's slug: `PATCH /api/v1/tenants/{tenant}` with a new `slug` | `TenantService.UpdateTenant` |
| Allowing bearer-key sensors again: `PUT /api/v1/sensors/identity-policy` with `bearer_keys_allowed: true` while the organization requires key-bound identity | `SensorService.SetBearerKeysAllowed` (requiring key-bound identity, and re-sending the current value, stay one click) |

The gate judges only the user making the request: a grant authorized
earlier and applied for someone else (an invitation accepted by the invitee,
SCIM, SSO just-in-time provisioning) is not asked again. There is no separate
ownership-transfer action: making someone an owner is the owner-role grant
above.

Sensor pairing approval (`POST /api/v1/sensor-pairings/{id}/approve`, RFC-052)
checks a step-up proof inside the request body with the same
`VerifyStepUp`. Changing a sensor's grant (`PUT /api/v1/sensors/{id}/grant`)
asks for step-up only when the change widens the grant or promotes the
sensor: the grant service knows that, so the check runs there
(`handler.StepUpWideningApprover`, `middleware.CheckRecentAuth`) and the
answer is the same 403 `STEP_UP_REQUIRED`. Narrowing stays one click. Reads
and cosmetic changes never prompt.

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
