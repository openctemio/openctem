# Linking Google, GitHub and Microsoft sign-in to an account

A person can sign in to one account with a password and with one or more social
providers (Google, GitHub, Microsoft). Each provider identity is a row in
`user_identities` (issuer, subject), the same store organization SSO uses
([accounts are keyed on the identity provider's user id](sso-authentication.md#accounts-are-keyed-on-the-identity-providers-user-id)).
A sign-in finds the account by that pair first; the e-mail address only matters
the first time.

Code: `internal/app/auth/identity_link.go` (service),
`internal/infra/http/handler/identity_link_handler.go`,
`internal/infra/http/routes/auth.go` (`registerIdentityLinkRoutes`), web
`features/account/components/sign-in-methods-card.tsx` and
`app/auth/callback/[provider]/route.ts`.

## When the address already has an account

A social sign-in whose provider-verified address belongs to an account that
signs in another way (a password account, or an account of another provider)
and whose provider identity is not linked to it changes nothing on that
account and signs nobody in. It is refused with `409 OAUTH_ACCOUNT_EXISTS`.
Linking always needs the person to prove the account too: from Account >
Security, or by signing in to it right away and confirming (below). Automatic
linking is off unless the platform turns it on.

### Confirming the link after signing in

When the identity could be linked (the account is active and holds no other
identity of that provider), the refusal leaves a pending link:

1. The API stores the provider identity (issuer, subject), its address and the
   account it collided with, for 10 minutes, under the SHA-256 of a random
   32-byte secret. Nothing on the account changes.
2. The secret travels only in an HttpOnly cookie (`__Host-oauth_pending_link`
   with Secure cookies, `oauth_pending_link` without; SameSite=Lax, Path=/,
   10 minutes) set on the 409; the body says only
   `details: {link_pending: true, provider}`. The web server relays that
   cookie to the browser and never shows the secret to page script. The
   sign-in page says "An account with this email already exists. Sign in with
   your password or the way you signed in before, and we will ask you to
   confirm linking this provider."
3. The person signs in to the account the usual way: password and second
   factor, or the provider the account already uses. The provider never
   replaces that sign-in.
4. In the app, the web server (forwarding the cookie) describes the pending link
   (`POST /api/v1/me/pending-sign-in-link/describe`) and asks "Link Google
   account x to your account?" with the authenticator code (or the password)
   field in the same dialog. "Link" confirms with that proof
   (`POST /api/v1/me/pending-sign-in-link/complete`), "Not now" drops it
   (`POST /api/v1/me/pending-sign-in-link/cancel`). The cookie is deleted
   either way, except after a missing or wrong proof (`LINK_PROOF_REQUIRED`,
   `LINK_PROOF_FAILED`), when the person can type it again. The routes read the secret from the cookie only, never from the
   body or the URL.
5. The confirm is accepted only with a proof typed for it (see
   [Proof at the moment of the change](#proof-at-the-moment-of-the-change);
   the sign-in that just happened does not count), only from the account the
   pending link was made for, only from a session that signed in or stepped
   up after the pending link was made (the session's own server-side
   record), only with the secret, once, before it expires, and only
   while the account's address is still the provider's. A pending link
   presented by another account is spent. The link itself follows the
   explicit-link rules (identity linked elsewhere, second identity of the
   provider). Every other session of the account is then revoked, the link is
   audited (`how=after_sign_in`) and the account's mailbox is told.

| Route | Gate |
|---|---|
| `POST /api/v1/me/pending-sign-in-link/describe` | signed in, CSRF, rate limit; the pending link must be this account's |
| `POST /api/v1/me/pending-sign-in-link/complete` | proof typed for it (the sign-in that just happened does not count), CSRF, rate limit; authenticated after the pending link |
| `POST /api/v1/me/pending-sign-in-link/cancel` | signed in, CSRF, rate limit |

Refusals: `404 PENDING_LINK_INVALID` (none for this account: expired, used,
made for another account or never made; one answer for all; `400` with the
same code when the request has no pending-link cookie),
`403 PENDING_LINK_SIGN_IN_REQUIRED` (the session authenticated before the
pending link), `403 LINK_PROOF_*` (the proof), `409 IDENTITY_LINKED_ELSEWHERE` /
`PROVIDER_ALREADY_LINKED`.

## Proof at the moment of the change

Every change of an account's sign-in methods (starting an explicit link,
confirming a pending link, unlinking) needs a proof typed into its confirm
dialog and sent with that one request as `step_up` (`auth/link_proof.go`):

| The account has | Proof |
|---|---|
| TOTP | A current authenticator code. Never a recovery code; a code from an already used time step is refused, so the code that signed the person in a moment ago cannot be replayed here. A password is not accepted instead. |
| A password, no TOTP | The password. |
| Neither (signs in only through a provider) | None possible: `403 LINK_PROOF_UNAVAILABLE`. The person turns on two-factor authentication first. |

A recent sign-in or an open [step-up window](step-up-reauth.md) does not count,
so these routes are not behind `requireStepUp`: the service checks the proof
itself, and a closed window does not ask for a second, separate proof first.
The proof authorizes only its request; it never opens a window on the session.
Passkeys exist only for platform administrators (the admin console), so a
tenant account never presents one here.

Refusals: `403 LINK_PROOF_REQUIRED` (no proof of the kind the account needs),
`403 LINK_PROOF_FAILED` (wrong, reused or recovery code, wrong password),
`403 LINK_PROOF_UNAVAILABLE`, `403 ACCOUNT_LOCKED`. A wrong proof counts towards
the account lockout exactly like a failed sign-in, on top of the routes' rate
limit. Every attempt writes `auth.step_up` / `auth.step_up_failed` with
`method` (`totp` or `password`) and `purpose` (`link_start`, `pending_link`,
`unlink`); the link and unlink events themselves carry `factor`. For an
explicit link, the factor that proved the start is kept server side with the
link's PKCE record and taken at the callback: a link whose start was never
proved does not complete. `GET /api/v1/me/sign-in-methods` and the pending-link
describe return `proof` (`totp`, `password` or empty) so the dialog asks for
the right field.

## Explicit linking (Account > Security)

"Connected sign-in methods" lists the password (when the account has one), the
linked providers and the organization SSO identities (read only).

| Route | Gate |
|---|---|
| `GET /api/v1/me/sign-in-methods` | signed in |
| `POST /api/v1/me/sign-in-method-links/{provider}/start` | proof typed for it, CSRF, rate limit |
| `POST /api/v1/me/sign-in-method-links/{provider}/complete` | signed in, rate limit; state bound to account, session and browser, single use, expires |
| `DELETE /api/v1/me/sign-in-methods/{id}` | proof typed for it, CSRF, rate limit |

Link flow:

1. "Link" opens a dialog that asks for the authenticator code (or the
   password); the browser calls the link start with it through the API
   client. A refused proof is shown in the dialog.
2. The API returns the provider's authorization URL. Its signed state carries
   `purpose=link`, the account id, the session id and an expiry; the PKCE
   verifier is kept server side under the state, single use, for the state's
   lifetime, together with the hash of a one-time browser-binding secret
   returned as `browser_binding`. This is the same record a sign-in keeps
   (`storeBoundVerifier` in `auth/oauth.go`).
3. A server action keeps the state, the browser binding (the same
   `__Host-oauth_binding` cookie a sign-in uses) and a link-intent cookie naming the
   provider in httpOnly cookies; the browser goes to the provider.
4. The provider redirects to `/auth/callback/{provider}`, the redirect URI
   already registered for sign-in. The route sees the link intent, checks the
   state cookie, takes the binding cookie (single use), and calls the link
   callback with the session cookie's token and `browser_binding`.
5. The API accepts the state only when its purpose is `link` and its account
   and session are the caller's and it has not expired, then takes its PKCE
   record (deleted on read, so a replay finds nothing) and refuses it unless
   `browser_binding` hashes to the stored binding. Every refusal is the same
   `400 OAUTH_INVALID_STATE`, before the code exchange. It then exchanges the code, reads the verified
   identity and binds it. It refuses an identity linked to another account
   (`409 IDENTITY_LINKED_ELSEWHERE`) and a second identity of the same
   provider (`409 PROVIDER_ALREADY_LINKED`).
6. The browser lands on `/account/security?linked=<provider>` or
   `?link_error=<CODE>`; the page shows its own text for the code.

The provider's address does not have to match the account's: the person proved
both. A link never changes the account's address, and a provider linked to a
password account never rewrites it later either (the address moves with the
provider only on an account that provider created).

Unlinking removes one Google, GitHub or Microsoft identity. The account's last
sign-in method is never removed (`409 LAST_SIGN_IN_METHOD`): an account without
a password keeps at least one identity, and the check runs with the account row
locked so two concurrent unlinks cannot remove the last two. Organization SSO
identities are managed by the organization (`409 IDENTITY_MANAGED_BY_ORGANIZATION`).

Each link and unlink writes `auth.identity_linked` / `auth.identity_unlinked`
(security, high) and e-mails the account's address.

## Automatic linking (off by default)

The platform can let a social sign-in link itself to an existing password
account with the same address, instead of answering `OAUTH_ACCOUNT_EXISTS`.
It is off unless an operator turns it on in Console > Settings > Sign-up,
"Link Google and Microsoft sign-in to existing accounts" (`social_auto_link`;
absent or unreadable is off; the change is audited and the other
administrators are told). Even then it applies only when all hold:

| Condition | Why |
|---|---|
| The operator turned it on | Mailbox control alone then signs into the account (subject to its second factor); an operator whose accounts were ever created without proof of the address, or whose domains may change hands, keeps it off |
| The provider is authoritative for the address: Google on `gmail.com`/`googlemail.com`, or a Workspace account whose `hd` claim equals the address domain; Microsoft with the domain-owner-verified claim; never GitHub | The provider must run the mailbox, not merely have seen the address once ([Social sign-in and the e-mail it can prove](user-onboarding.md#social-sign-in-and-the-e-mail-it-can-prove)) |
| The provider marked the address verified (Google `email_verified`, Microsoft `xms_edov`) | Required by the sign-in itself |
| The account has a password and its address is verified | Mitigates pre-hijacking, below; an account made by another provider is never linked automatically |
| The account is active and has no other identity of that provider | A second subject from one issuer is a different person |

On an automatic link every session of the account is revoked, a pending
password reset link is cancelled, the link is audited (`how=automatic`) and the
account's mailbox is told.

A stored `social_auto_link` from before the default changed is dropped by the
migration `signup_policy_social_auto_link_off` (the console sent the old
default back with every save, so it did not show a choice).

## The provider changes its address

A returning identity is found by (issuer, subject), never by address. On an
account the provider created, a new verified address replaces the old one when
no other account holds it; it counts as verified only where the provider is
authoritative for it (as at account creation), otherwise the account's address
becomes unverified and cannot claim invitations or join an organization by
domain until verified another way. A provider linked to a password account
never changes its address.

## Second factor after the provider

A password account signed into through a linked provider (explicit or
automatic) takes exactly the second step its password sign-in takes: with an
authenticator on, the callback answers the same challenge as the password
sign-in (`mfa_required`, `mfa_token`) and no session; with an organization that
requires two-factor and no factor yet, the enrollment challenge. The web keeps
the challenge in the httpOnly `mfa_challenge` cookie and the sign-in page asks
for the code (`/login?mfa=verify`). The provider replaces the password, never
the second factor. Without the second-factor gate wired, a password account is
never signed in through a provider (fail closed).

Accounts created by a provider (no password) are unchanged: their second factor
is the provider's, as before.

## Organization policies

Linking changes how a person proves who they are, not what they may do.
Organization policies apply to the session exactly as before:

- A provider session without our second step is stamped `sso` with no issuing
  organization: an organization that enforces its own SSO, or requires
  two-factor, refuses it at token mint and the person signs in through the
  organization's SSO or with password and second factor.
- After the second step above, the session is the one the password sign-in
  issues, with the same second-factor standing.
- Personal-account policies, allowed domains, IP allowlists and memberships are
  checked per organization at token mint, unchanged.

## Threat model

| Threat | Mitigation |
|---|---|
| Account takeover with a provider account carrying the victim's address the provider does not own (consumer Google account on a company address, GitHub address) | Automatic linking needs an authoritative provider; GitHub never links automatically; otherwise `OAUTH_ACCOUNT_EXISTS` |
| Unverified provider address | Google and Microsoft sign-in already refuse an unverified address; GitHub reads only its primary verified address |
| Pre-hijacking: an attacker registers the victim's Gmail address with a password before the victim arrives through Google | Automatic linking needs the account's address verified (the attacker cannot click the link sent to the victim's mailbox); on a link every session is revoked and a pending reset link cancelled, and the mailbox (the victim) is told. Residual: an address marked verified without mailbox proof (an administrator-provisioned account with a temporary password, or a deployment that ran without mail delivery); the administrator turns automatic linking off for such deployments |
| Second-factor bypass through a provider | The linked password account gets the same second step as its password sign-in |
| Link CSRF (an attacker's provider account linked to the victim's session) | The link start needs a proof typed for it and the CSRF token; the state is signed, single use, expires, and bound to the account and session that started it; the callback also checks the state cookie of the browser |
| Cross-browser completion (the attacker's code and state, or the victim's leaked callback URL, finished in another browser) | The PKCE verifier is released only with the browser-binding secret held in an HttpOnly cookie of the browser that started the link; a wrong or missing secret spends the record, so the starting browser cannot be raced either |
| State replay (a used state and code from a log or Referer) | The PKCE record is deleted on first read; a replay is refused before any code exchange |
| Using a link state to sign in, or a sign-in state to link | The sign-in callback refuses a state with a purpose; the link callback accepts only `purpose=link` |
| Removing someone else's identity | Unlink deletes by (identity id, account id of the session); another account's identity is not found |
| Locking oneself out | The last sign-in method stays; checked under a row lock |
| Account enumeration | `OAUTH_ACCOUNT_EXISTS` and `IDENTITY_LINKED_ELSEWHERE` are answered only after the provider proved the person holds that address or provider account; the pending-link refusals have one answer for every reason |
| Linking by mailbox control alone (a recycled or transferred mailbox or domain, a compromised provider account) | Off by default: a social sign-in never changes an existing account; the person must sign in to the account and confirm |
| Planting or stealing a pending link | The secret is never in a response body or URL, only in an HttpOnly `__Host-` cookie (no subdomain or script can read or set it); the record is bound to the account it collided with, so another account cannot confirm or even read it, and presenting it spends it |
| Confirming with a session someone already held (stolen session, shared computer) | The confirm needs the authenticator code (or the password) typed for it, and a session that signed in or stepped up after the pending link was made; on confirm every other session is revoked and the mailbox is told |
| Linking or unlinking from a stolen or unattended session | Every change needs a proof typed for that request; a recent sign-in or step-up window does not count; wrong proofs count towards the lockout |
| Replaying the sign-in's code to confirm | TOTP time steps are single use (`mfa_factors.last_used_step`); recovery codes are refused |
| Replay of a pending link | Single use (GETDEL), 10 minutes, hash-only storage |
| A provider's later address counted as proven | The new address is verified only where the provider is authoritative |
| Organization SSO enforcement or two-factor floor bypassed through social sign-in | A social session is stamped `sso` with no issuing organization: enforcement and the two-factor requirement treat it as a password session without our second factor (`Session.FederatedFor`), so it is refused at token mint |
| Platform administration through social sign-in | The console needs its own sign-in and second factor; its identity provider bindings are separate from social identities, and break-glass accounts are refused on every main-site path |

Tenant isolation: users and identities are global (not organization data); every
route acts on the session's own account only, no request field names an
account, and the linking tables hold no organization data. A SAML identity
stays scoped to its organization and is never shown as unlinkable.
