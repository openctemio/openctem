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
and whose provider identity is not linked to it is refused with
`409 OAUTH_ACCOUNT_EXISTS`. Nothing is written. The sign-in page keeps a notice:
sign in with your password, then link the provider in Account > Security, with
a password reset link. Earlier versions answered `500 INTERNAL_ERROR`.

The only exception is automatic linking, below.

## Explicit linking (Account > Security)

"Connected sign-in methods" lists the password (when the account has one), the
linked providers and the organization SSO identities (read only).

| Route | Gate |
|---|---|
| `GET /api/v1/users/me/identities` | signed in |
| `POST /api/v1/users/me/identities/{provider}/link` | step-up, CSRF, rate limit |
| `POST /api/v1/users/me/identities/{provider}/link/callback` | signed in, rate limit; state bound to account and session |
| `DELETE /api/v1/users/me/identities/{id}` | step-up, CSRF, rate limit |

Link flow:

1. The browser calls the link start through the API client. A session that has
   not re-authenticated in the step-up window gets `403 STEP_UP_REQUIRED` and
   the dialog asks for the authenticator code or password first.
2. The API returns the provider's authorization URL. Its signed state carries
   `purpose=link`, the account id and the session id; the PKCE verifier is kept
   server side under the state, single use.
3. A server action keeps the state (and a link-intent cookie naming the
   provider) in httpOnly cookies; the browser goes to the provider.
4. The provider redirects to `/auth/callback/{provider}`, the redirect URI
   already registered for sign-in. The route sees the link intent, checks the
   state cookie, and calls the link callback with the session cookie's token.
5. The API accepts the state only when its purpose is `link` and its account
   and session are the caller's, exchanges the code, reads the verified
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

## Automatic linking

A social sign-in links itself to an existing password account with the same
address, instead of answering `OAUTH_ACCOUNT_EXISTS`, only when all hold:

| Condition | Why |
|---|---|
| The platform allows it: Console > Settings > Sign-up, "Link Google and Microsoft sign-in to existing accounts" (`social_auto_link`, on by default; an unreadable policy is off) | An operator whose accounts were ever created without proof of the address can turn it off |
| The provider is authoritative for the address: Google on `gmail.com`/`googlemail.com`, or a Workspace account whose `hd` claim equals the address domain; Microsoft with the domain-owner-verified claim; never GitHub | The provider must run the mailbox, not merely have seen the address once ([Social sign-in and the e-mail it can prove](user-onboarding.md#social-sign-in-and-the-e-mail-it-can-prove)) |
| The provider marked the address verified (Google `email_verified`, Microsoft `xms_edov`) | Required by the sign-in itself |
| The account's own address is verified | Mitigates pre-hijacking, below |
| The account is active and has no other identity of that provider | A second subject from one issuer is a different person |

On an automatic link every session of the account is revoked, a pending
password reset link is cancelled, the link is audited (`how=automatic`) and the
account's mailbox is told.

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
| Link CSRF (an attacker's provider account linked to the victim's session) | The link start needs step-up and the CSRF token; the state is signed, single use, and bound to the account and session that started it; the callback also checks the state cookie of the browser |
| Using a link state to sign in, or a sign-in state to link | The sign-in callback refuses a state with a purpose; the link callback accepts only `purpose=link` |
| Removing someone else's identity | Unlink deletes by (identity id, account id of the session); another account's identity is not found |
| Locking oneself out | The last sign-in method stays; checked under a row lock |
| Account enumeration | `OAUTH_ACCOUNT_EXISTS` and `IDENTITY_LINKED_ELSEWHERE` are answered only after the provider proved the person holds that address or provider account |

Tenant isolation: users and identities are global (not organization data); every
route acts on the session's own account only, no request field names an
account, and the linking tables hold no organization data. A SAML identity
stays scoped to its organization and is never shown as unlinkable.
