### Fixed: sign-in refusals say what the person can do, in their language

- Every refusal of a sign-in, single sign-on, SAML, social sign-in or invitation now carries a stable `code` from one table (`handler/auth_error_codes.go`). The services return sentinel errors, not sentences. The web console words each code in English and Vietnamese and no longer shows the server's sentence when the code is known.
- Expected refusals answer 4xx instead of 500: an identity provider response that fails verification, one without an email address, and sign-up closed for single sign-on.
- New codes tell the person what to do: `SSO_AWAITING_APPROVAL`, `SSO_NOT_A_MEMBER`, `LIMIT_REACHED` (no free seat), `SSO_DOMAIN_NOT_ALLOWED`, `ACCOUNT_LINK_REQUIRED`, `SSO_REQUIRED`, `SSO_DIFFERENT_METHOD`, `EMAIL_UNVERIFIED_AT_IDP`, `USE_ADMIN_CONSOLE`, `ACCOUNT_SUSPENDED`, `EMAIL_NOT_VERIFIED`, `ORGANIZATION_SUSPENDED`. A SAML failure redirects to `/login?error=<code>` instead of one generic flag, and both callback pages show the matching message. The answers before the password is proven stay generic, and none names another organization.
- "This email is registered with a different login method" is its own refusal (`SSO_DIFFERENT_METHOD`); it was reported as "Your email domain is not allowed".
- A platform administrator who signs in through an identity provider is told to use the admin console (`USE_ADMIN_CONSOLE`) instead of a generic failure.
- Invitation refusals (already a member, membership suspended, reactivate instead of inviting) have codes `INVITATION_ALREADY_MEMBER`, `INVITATION_MEMBERSHIP_SUSPENDED` and `MEMBERSHIP_SUSPENDED_REACTIVATE`.
- The `MFA_ENROLLMENT_REQUIRED` answer for a session that must prove a second factor through its identity provider is now `MFA_IDP_EVIDENCE_REQUIRED`.
- The wrong "Must be admin, member, or viewer" default-role message now says member or viewer.
- Error and dictionary text follows the text rules: no em dashes or middle dots, "organization" instead of "team". `scripts/check-separators.sh` checks the sign-in dictionaries whole and the API error strings it adds.

### Removed: `email_verification_required` from `GET /auth/info`

- The field reported the configured flag, not the rule that applies to a person (an organization can tighten it). Nothing read it.
