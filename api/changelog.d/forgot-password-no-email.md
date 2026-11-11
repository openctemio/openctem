### Security: forgot-password no longer voids a handed-over link when email is off

- On an installation that cannot send email, `POST /api/v1/auth/forgot-password` issued a reset token it
  could not send. The token replaced the account's stored link, which is also where an administrator's
  one-time setup or reset link lives, so anyone who knew the address could make that link stop working.
  Nothing is issued now while email is off; the answer is unchanged.
