### Security: a social sign-in no longer signs in an identity the organization's single sign-on manages

- A Google or Microsoft social sign-in whose provider identity was created by an organization's Entra ID or Google Workspace sign-on (identity source `sso`) used to sign the person in. It is now refused with `409 OAUTH_USE_ORG_SSO` ("This account signs in through your organization. Use your organization's sign-in."): the person never confirmed that route. No session opens, nothing on the account changes, and the refusal is audited (`auth.failed`, user id and provider only).
- The sign-in page shows the message and the organization sign-in offered for the typed work email.
- Behaviour change: such a person must use the organization's sign-in; a social identity and the organization's own sign-on work as before.
