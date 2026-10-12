### Security: a password longer than 72 bytes is refused before the account lookup

- Registration, password reset, password change and the admin console refuse a
  password longer than 72 bytes (bcrypt's limit) with a 400 that says so. Such
  a password used to pass validation and then fail as a 500 when hashed. At
  registration the hash only runs for a new email, so an existing email got
  the usual "check your email" answer and a new one a 500: an account
  enumeration oracle. A letter with an accent takes 2 or more bytes.
- The minimum length now counts characters, not bytes, so six accented
  letters no longer satisfy a 12-character minimum.
