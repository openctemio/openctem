### Security: public sign-in endpoints no longer reveal organizations or accounts

- `GET /auth/sso/providers?org=` answers an unknown organization with
  `{"providers":[]}` (200), like an organization without SSO; before it was a
  404 "Organization not found". `GET /auth/sso/{provider}/authorize` answers an
  unknown organization like a missing provider (404 "SSO provider not
  configured"). `GET /auth/saml/{org}/metadata` serves the SP metadata for any
  well-formed slug.
- `POST /auth/register` answers a new and an already registered email with the
  same body: it no longer returns the account id, states the same
  verification rule for both, checks the password policy before the account
  lookup (a weak password was refused only for a new email), and sends the
  verification email after the response.
- `POST /auth/forgot-password` does the lookup, the token write and the email
  after the response, so its latency does not depend on the account existing.
