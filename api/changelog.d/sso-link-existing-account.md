### Security: an organization's sign-in never rewrites a password account's address

- A sign-in through an organization's identity provider adopts the address the provider sends only for an account without a password. A password account linked to the organization's sign-in keeps its address, which is how it signs in and recovers its password in every organization.

### Added: a password account links its organization's single sign-on

- Account > Security has an "Organization sign-in" card: a member whose account has a password (every organization's first owner, created by local sign-up) links the organization's Entra ID, Okta or Google Workspace sign-in, and can then sign in through it. Before, such a sign-in was refused with "link this identity provider" and there was no way to do so, so "Require single sign-on" could not be satisfied for that owner.
- Linking and unlinking need an explicit confirmation and a proof typed at that moment (the authenticator code, or the password when two-factor authentication is off), and the identity provider is asked to authenticate the person again. The link is bound to the account, the session and the browser that started it, single use, and only for an active member of the organization; an identity of another account is refused. Linking signs the account out of its other devices, is audited (also in the organization's audit log) and e-mailed. No session is issued by a link.
- The sign-in error for an existing account now points to Account > Security.
- API: `GET /api/v1/me/sso-links`, `POST /api/v1/me/sso-links/{provider}/start`, `POST /api/v1/me/sso-links/{provider}/complete`, `DELETE /api/v1/me/sso-links/{id}`. SAML linking is not included yet.
- A state store that cannot be read no longer lets an identity-link state pass as an ordinary sign-in: the sign-in callback and the link completion refuse it (invalid state).
- The link confirmation says that after linking, signing in through the organization's identity provider opens the account without the account's own second factor, so that provider's administrator controls access to it.
