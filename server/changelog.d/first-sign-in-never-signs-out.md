### Fixed: a first sign-in with Google, GitHub or Microsoft no longer ends back on the sign-in page

- A person signing in with a social provider for the first time (no organization yet) was signed
  out at once: the web landed them on the dashboard with a token that has no organization, its
  first organization request answered `401 TENANT_REQUIRED`, the refresh had no organization to
  renew, and the client took that as a dead session. The web now decides the landing from the
  person's memberships (`/auth/continue`): no organization opens the account space (`/welcome`,
  or the invitation they came from), one opens it, several open the picker.
- The browser signs a person out only when the session itself is gone (the refresh is refused
  with 401, or the session came from another organization's identity provider). A route that
  needs an organization, an organization that requires two-factor authentication, a suspended
  organization, or a server error never signs anybody out.
- Turning two-factor authentication on, or moving it to a new authenticator, now sends the person an
  e-mail (`notice.mfaOn`, `notice.mfaReplaced`, en and vi) from every path, so a hijacked session
  that binds its own authenticator is noticed. A social sign-in is refused when the second-factor
  gate is not wired (fail closed), and the in-place enrolment step is for social-provider
  accounts only.
- Docs: server/docs/architecture/tenantless-account-space.md

### Behaviour change: social sign-in accounts can satisfy an organization's two-factor requirement

- An account that signs in only with Google, GitHub or Microsoft and is invited into an
  organization that requires two-factor authentication could never get in: the organization
  refused the social session, the account token was refused because the person now had an
  organization, and the in-place setup refused social sessions. Now the social sign-in counts as
  the first factor: the session step (`POST /auth/mfa/enroll/session`, within 15 minutes of
  signing in) enrolls or verifies our authenticator code in place, and every later social
  sign-in of an account with a factor, or of a member of an organization that requires one, asks
  for the code before any session is issued. A session issued by an organization's own identity
  provider still cannot start that step (that provider owns the factor). Account > Security
  offers the setup to such accounts (turning it off needs a password and is not offered).
- `POST /auth/account-token` now answers `200` for any signed-in account, member of an
  organization or not (it answered `409` for members). The token reaches only the account routes,
  so it skips none of an organization's rules; those apply when the session asks for that
  organization's token. Both tokens are bound to the same session. `GET /me/sso-links` and the
  organization sign-in link routes are on the account allow-list.
- Docs: server/docs/architecture/user-two-factor-authentication.md, server/docs/rfcs/RFC-141-tenantless-account-space.md
