### Fixed: password forms state the server's password policy

- `GET /api/v1/auth/providers` reports `password_policy`: the minimum
  length, the required character classes and how long a forgot-password link
  stays valid (`reset_link_valid_minutes`), from `AUTH_PASSWORD_*` and
  `AUTH_PASSWORD_RESET_DURATION`.
- The register, set-password, reset-password and change-password forms (and
  the platform console's temporary-password change) state and pre-check that
  policy instead of their own copy: change-password said "at least 8
  characters" while the server requires 12 by default, plus an uppercase
  letter, a lowercase letter and a number.
- The forgot-password confirmation said the link lasts 24 hours; it now
  states the configured lifetime (1 hour by default).
