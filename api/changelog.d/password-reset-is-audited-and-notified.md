### Security: a password reset is audited and the account holder is told

- Completing a reset by emailed link writes `auth.password_changed` (with
  `via=reset`, the caller's IP and user agent) and sends the "your password
  was changed" email, like a change from the account page. Before, a reset by
  someone with access to the mailbox left no audit event and no notice.
- A first password set from an administrator's setup link is audited with
  `via=setup` and sends no change notice.
- The emailed link proves the address, so it also verifies an email that was
  still waiting for verification.
