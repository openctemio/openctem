### Added: recovery paths for a server that cannot send email

- `GET /api/v1/auth/providers` reports `email_delivery`. The forgot-password page says "ask your administrator for a reset link" instead of promising an email, and the members page shows a "This server cannot send email" banner. `GET /api/v1/me/bootstrap` carries the same `email_delivery` flag, so dashboard pages read it without asking `/auth/providers`.
- Console > Users: a super admin can copy a one-hour password reset link (shown once, stored only as a hash, never logged or written to the audit row, refused while email works), mark an email verified, and reset a user's two-factor authentication (needs a second super admin's approval, ends every session).
- Invitations: `POST /tenants/{tenant}/invitations/{id}/link` copies a new link (the token rotates, no email) and `.../renew` renews an expired invitation. The members page offers "Copy new link" and "Renew".
- `POST /auth/resend-verification` sends the verification link again (always 202, one email per address every two minutes). The verification failure page and a sign-in refused with `EMAIL_NOT_VERIFIED` offer it.

### Fixed: a reset link works once, and a declined invitation must be pending

- Of two requests that present the same password reset link at the same moment, exactly one now succeeds: the token is cleared by a conditional update.
- Declining an invitation through the public decline route is refused (409) unless the invitation is pending, so an accepted invitation is no longer revoked and audited as declined.
