### Security: organizations can require their identity provider to prove two-factor

- New organization setting `sso_require_mfa_evidence` ("SSO must prove two-factor", Settings > Security > Authentication). When it is on, a member who must use two-factor authentication and signs in through the organization's own SAML or OIDC provider gets a token only if that sign-in carried the provider's signed proof of a second factor (`amr` containing `mfa`, or a multi-factor SAML authentication context). Before, a sign-in through the organization's own provider always passed the two-factor requirement.
- Token exchange and refresh refuse such a session with `403 MFA_ENROLLMENT_REQUIRED`. Off by default; changing it needs the owner with step-up, and turning it off is audited as High.
