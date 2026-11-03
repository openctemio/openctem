### Security: step-up says why a code was refused, and each code is sent once

- `auth.step_up_failed` audit events record the reason (`invalid_code`, `replayed_code`, `invalid_password`, `account_locked`, `no_totp_factor`, `decrypt_error`, `rate_limited`), never the code. A rate-limited step-up is audited once a minute per person.
- `POST /api/v1/auth/step-up` answers `403 STEP_UP_CODE_USED` for a code from an already used time step (still refused and counted towards the lockout); an unreadable authenticator secret is a server error, no longer reported as a wrong code and not counted towards the lockout. A code typed as `123-456` is accepted.
- The confirm dialog sends each code once (auto-submit, Confirm and Enter share one lock), shows distinct messages for a wrong code (naming the host whose authenticator entry to use), a used code and too many attempts.
- New authenticator entries are labelled with the host, e.g. `OpenCTEM (app.example.com)`, so entries of two installations can be told apart. Existing entries are unchanged.
- The verification-code field is centred in every dialog and screen that uses it.
