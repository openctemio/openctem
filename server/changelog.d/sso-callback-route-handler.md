### Fixed: organization SSO sign-in completes in the web app

- The organization SSO callback (`/auth/sso/callback/{provider}`, Microsoft Entra ID, Okta, Google Workspace) is now a route handler. As a page, writing the session cookies threw "Cookies can only be modified in a Server Action or Route Handler" and every organization SSO sign-in landed back on the sign-in page.

### Changed: the Entra ID setup guide in the admin console no longer offers a logout URL

- Microsoft Entra ID sends no back-channel logout and does not notify on a disabled or deleted user, so the guide no longer asks for a "Front-channel logout URL" or the `sid` claim. It says that disabling a user in Entra does not end their sessions and points to SCIM provisioning.
- Every exit of the organization SSO callback, including an unknown provider, a provider error, missing parameters and an early state failure, clears the single-use state, return-path and browser-binding cookies.
