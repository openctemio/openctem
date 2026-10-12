### Added: the web console asks to confirm your identity before sensitive actions

- When the API answers `403 STEP_UP_REQUIRED`, one shared dialog asks for an authenticator code (accounts with two-factor authentication) or the password, calls `POST /api/v1/auth/step-up`, and retries the action once. SSO accounts without an authenticator are offered "Sign in again". Cancelling leaves the action undone.
