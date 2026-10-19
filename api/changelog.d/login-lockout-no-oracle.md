### Security: a locked account no longer reveals a correct password, and lockouts back off

- A sign-in to a locked account answers "invalid email or password" for the right and the wrong password alike (it used to answer 403 "locked" only to the right one, telling a guesser who rotates source addresses which guess was right). The console password step behaves the same way.
- Every attempt against a locked account now counts. The lock grows with each further run of `AUTH_MAX_LOGIN_ATTEMPTS` failures (15 minutes, then 30, 60, ... up to 24 hours), so per-account guessing is bounded whatever the number of source addresses.
- Setting a new password (reset link or change) clears the failure count and the lock, so the owner of a locked account gets back in through forgot-password.
