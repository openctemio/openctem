### Added: SAML setup from metadata files in the admin console

- The SAML form of an organization (admin console, Single sign-on) downloads the service provider metadata as an XML file (`GET /api/v1/admin/tenants/{tenantId}/sso/saml/sp-metadata`) to upload in the identity provider's SAML application.
- It also imports the identity provider side (entity ID, sign-in URL, signing certificates) from the IdP's federation metadata URL, for Microsoft Entra ID the App Federation Metadata Url, or from an uploaded metadata file (`POST /api/v1/admin/tenants/{tenantId}/sso/saml/idp-metadata`). The import only fills the form; saving still waits for an owner's approval.
- The fetch is https only through the outbound SSRF guard (every redirect checked), capped at 1 MiB and 10 seconds; a document with a DOCTYPE or entity declaration is refused; certificates are taken only from the signing keys of the SAML IdP descriptor.

### Changed: a SAML configuration may trust several IdP signing certificates

- `idp_certificate` accepts up to five PEM certificates (the IdP's current and next signing key), so a key rollover at the IdP does not stop sign-in. Any configured, unexpired certificate verifies an assertion. The expiry shown and alerted on is the soonest one among the unexpired certificates.

### Fixed: the SAML form showed the console's address in the service provider URLs

- The URLs to register at the IdP are now built on the API's public address (`APP_URL`), the same one the SP metadata uses.
- With several signing certificates stored, an IdP that signs without an embedded certificate now signs in: each stored certificate is tried in turn (each still checked for validity); a signature that embeds a certificate must still match a stored one.
- A metadata URL that is unreachable, answers something malformed, or answers something that is not SAML metadata is refused with one reason in the response; the detail is logged server-side.
