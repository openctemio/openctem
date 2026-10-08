### Added: email-first sign-in

- `POST /api/v1/auth/discover {"email"}` answers `{"next":"sso","org":slug}`
  when the email's domain is claimed (DNS-verified, exclusive) by an
  organization with an active SSO provider, else `{"next":"password","org":""}`.
  The answer has the same shape for every email and never says whether the
  email has an account. Rate-limited (20/min per address).
- The sign-in page asks it as you type and shows the organization's SSO
  buttons, so `?org=` is no longer needed.
