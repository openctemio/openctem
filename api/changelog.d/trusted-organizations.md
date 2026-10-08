### Added: trusted organizations — sign in to a sister company with your own company's single sign-on

- **Request and acceptance** (RFC-058 part 2):
  - an organization's owner can trust another organization, named by a domain it verified for SSO (`POST /api/v1/organization/trusts`);
  - that organization's owner accepts (`POST /api/v1/organization/trusts/{trust_id}/approve`);
  - either owner can end it (`DELETE`);
  - every change needs step-up, is audited in both organizations' logs, and both sides are notified.
- **Signing in:** once accepted, external members from the trusted organization can sign in with a session from their own company's identity provider. This also satisfies a host that enforces SSO.
  - It is never weaker than the host's policy: a host requiring 2FA needs MFA evidence from the provider (`amr`, SAML AuthnContext) or the other organization's attestation that its IdP enforces MFA.
  - Password sessions, social logins and third organizations' providers never count.
- **What the trust controls:**
  - a role ceiling (viewer or member; never administrator or owner);
  - whether those members may create API keys (off by default; a key never outlives their access);
  - an optional default end of access.
- **Ending a trust** suspends the host's members from that organization, in the host only.
- Migration 001318: `tenant_trusts`, `sessions.mfa_evidence`.
