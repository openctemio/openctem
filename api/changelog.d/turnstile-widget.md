### Added: CAPTCHA widget on the request-access form

- With `CAPTCHA_TURNSTILE_SECRET` and `CAPTCHA_TURNSTILE_SITE_KEY` set, the request-access form shows the Cloudflare Turnstile widget and sends its token; sending waits for a valid token.
- The Content-Security-Policy allows `https://challenges.cloudflare.com` only on `/request-access` and `/register` (script, frame, connect); every other page is unchanged (`frame-src 'none'`), and the per-request script nonce stays.
