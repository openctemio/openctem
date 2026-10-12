### Security: SSO, SAML and social sign-ins are audited with the browser's device

- A sign-in through an organization's identity provider (OIDC or SAML) or a
  social provider now writes `auth.login` with `method` (sso, saml, oauth),
  the provider, the browser's IP address and user agent. An SSO or SAML
  sign-in is recorded in the issuing organization's audit log. Before, only
  the password sign-in was audited, so the sign-ins enterprise organizations
  rely on left no trace.
- Those sessions record the browser's address and user agent, so My account →
  Sessions shows the real device instead of a blank row. The web forwards the
  browser's User-Agent and address on the SSO and social sign-in calls, as it
  already did for the password sign-in.
