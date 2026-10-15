### Security: public sign-up always verifies the address

- Under `SIGNUP_MODE=domain` or `open`, every self-registered account must verify its email address
  before it can sign in. Before, verification was skipped when no SMTP server was configured, when
  the platform had exactly one organization whose `email_verification_mode` was `never` (that one
  organization's setting decided platform-wide sign-up), and when the registration carried an
  invitation token of an organization with `never` for another address.
- An organization's `email_verification_mode` now governs only the accounts invited into it. Under
  `SIGNUP_MODE=disabled` (the default) nothing changes: only invited and administrator-created
  accounts exist there.
