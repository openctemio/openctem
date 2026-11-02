### Security: an organization's Entra ID sign-in is pinned to its directory

- An organization's Microsoft Entra ID provider must name its directory by its GUID (Directory (tenant) ID). Saving one with an empty value, `common`, `organizations`, `consumers` or a domain name is refused; such a value let any Microsoft directory, personal accounts included, reach the sign-in checks, and a domain name could never match the token's `tid`.
- A stored Entra provider without a directory GUID is no longer offered on the sign-in page and refuses sign-in ("SSO provider not configured"). `SSO_ENTRA_TENANT_ID` (env fallback) must be a directory GUID, `common` or `organizations`.
- The SSO callback must present the same `redirect_uri` as the authorize request; another one is refused before the code is redeemed.
- **Upgrade note:** an organization whose Entra provider has no directory GUID must have it set in the admin console (Organizations > the organization > Single sign-on), which goes through the owner's approval as usual.
