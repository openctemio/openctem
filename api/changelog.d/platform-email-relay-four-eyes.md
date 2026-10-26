### Security: changing the mail server of platform e-mail needs a second super admin

- Saving platform e-mail turned on with a host, port or connection security that differs from the last relay applied while on now needs another super admin's approval first (`platform_email.relay`, 428 `SECOND_APPROVAL_REQUIRED`). The relay receives every set-password, password-reset and invitation link, so repointing it would let one session take over accounts. The approval is bound to the exact host, port and security.
- Rotating the username or password on the same relay, changing the sender, sending a test message and turning e-mail off stay one-person. With a single super admin the existing single-admin fallback applies (audited critical, every administrator told).
