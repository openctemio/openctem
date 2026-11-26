### Security: accounts signed in by an organization's single sign-on get no password by email

- A password-less account that an organization's single sign-on claimed or created can no longer set a password through forgot-password or a set-password link. Such a password would be a way in that the organization's identity provider does not control. Forgot-password gives the same answer as for any address and stores and sends nothing. A link that still reaches such an account answers "invalid or expired".
- The first single sign-on of a password-less account voids its outstanding set-password or reset link, such as the 24-hour link sent when an administrator created the user.
- Password accounts are unaffected. Organization owners and platform administrators keep forgot-password (break-glass), even when single sign-on manages their account.
- Docs: server/docs/architecture/sso-authentication.md (No password for accounts the organization's SSO manages)
