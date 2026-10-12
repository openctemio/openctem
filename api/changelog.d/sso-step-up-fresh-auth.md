### Security: step-up for SSO accounts needs a fresh sign-in at the identity provider

- A session created by an organization's identity provider (OIDC SSO, SAML) now opens the 10-minute step-up window only from the provider's signed authentication time (id_token `auth_time`, SAML `AuthnInstant`), not from the session's creation. A provider that signed the user in silently from a remembered session no longer unlocks sensitive actions.
- "Sign in again" in the step-up dialog asks the provider to authenticate the user again: `prompt=login` and `max_age=0` for OIDC (`reauth=true` on the authorize call), `ForceAuthn` for SAML (`reauth=1` on the login URL). The sign-in is refused when the provider answers with an authentication older than 5 minutes or without `auth_time`.
- Tokens from the external OIDC provider (`AUTH_PROVIDER=oidc`/`hybrid`) can now pass step-up routes: they are admitted while their signed `auth_time` is within the window (previously always `STEP_UP_UNAVAILABLE`).
- **Upgrade note:** for Entra ID, add the `auth_time` optional claim to the ID token in the app registration; without it, SSO users without an authenticator cannot complete step-up.
