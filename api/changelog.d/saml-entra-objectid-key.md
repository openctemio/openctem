### Security: SAML sign-ins from Entra ID are keyed on the Entra object id

- A SAML account binding is now keyed on Entra ID's `tenantid` + `objectidentifier` claims, which Entra sends in every assertion, instead of nothing (Entra's default email-format NameID keyed no identity, so the email alone found the account). A renamed or reused address no longer inherits the previous holder's account once that holder has signed in: another directory user presenting the same address is refused.
- Identities bound earlier under a persistent NameID are re-keyed to the object id on the next sign-in; other IdPs keep the persistent NameID rule. No operator action.
