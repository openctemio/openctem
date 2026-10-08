### Security: federated accounts are found by the identity provider's user id, not the email

- Organization SSO (OIDC, SAML) and social login (Google, GitHub, Microsoft) find the account by the provider's `(issuer, subject)` first: Entra and Microsoft by `oid`, Google by `sub`, GitHub by user id, SAML by a persistent `NameID` scoped to the organization. The organization OIDC path used to check the issuer only, so another user of the same directory presenting the same email was let in; a different subject is now refused.
- An email changed at the identity provider moves with the account instead of creating a second account or refusing the login. Organization SSO applies the new address only on a domain the organization DNS-verified, and never when another account holds it.
- Existing accounts are bound on their next login when the verified email matches and no other subject from that issuer is bound. Erasing a member's personal data removes their identities.
- Migration 001306 adds `user_identities` and copies `users.federated_issuer/federated_subject` into it. The old columns are no longer read or written; a later release drops them.
- **Upgrade note:** run the migrations before starting the new API.
