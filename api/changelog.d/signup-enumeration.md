### Security: sign-in discovery no longer returns organization slugs; CAPTCHA after repeated failed sign-ins

- `POST /api/v1/auth/discover` answers an opaque, expiring organization reference instead of the
  organization's slug; the SSO providers list and the authorize start accept it like a slug, so the
  sign-in page works unchanged.
- With Turnstile keys, a client address with 3 failed sign-ins in 15 minutes must pass the CAPTCHA
  before the next attempt (403 `CAPTCHA_REQUIRED`; counted per address, never per account). The
  sign-in page shows the check when asked (en, vi).
- Creating an organization with a URL that is taken answers one "this URL is not available"
  message without echoing the slug.
