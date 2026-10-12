### Security: a CAPTCHA protects self-service sign-up and request access

- With `CAPTCHA_TURNSTILE_SECRET` and `CAPTCHA_TURNSTILE_SITE_KEY` set,
  `POST /auth/register` requires a passing Cloudflare Turnstile token
  (`captcha_token`). It is checked before the account lookup, the same way for
  every address, and answers 400 `CAPTCHA_FAILED` otherwise. Request access
  already checked it.
- The register and request-access forms now render the check. Before, no form
  did, so setting the secret refused every request-access submission and
  registration had no CAPTCHA at all. Sign-up bots could create accounts and
  send verification emails from the platform's domain to any address.
- The server refuses to start with only one of the two variables. The web CSP
  allows frames from `https://challenges.cloudflare.com` only.
