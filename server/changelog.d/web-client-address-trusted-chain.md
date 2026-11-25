### Security: the web console passes on the client address only from a trusted proxy

- The web console's sign-in, password, second-factor, SSO and session calls to the
  API now follow `TRUST_PROXY_HEADERS` like its API proxy already did: with the
  setting off they send no client address, and the API sees the console's own.
- With the setting on, the console (and the platform console) sends the API one
  address: the right-most `X-Forwarded-For` entry, written by the proxy in front of
  it (`X-Real-IP` only when `X-Forwarded-For` is absent). Entries to its left and
  malformed values are not passed on.
- **Upgrade note:** none for the shipped Compose stack, the all-in-one image and the
  binary install, which set `TRUST_PROXY_HEADERS=true` behind the gateway. A setup
  that publishes the web console without a proxy in front of it should leave
  `TRUST_PROXY_HEADERS` off and not list the console in `SERVER_TRUSTED_PROXIES`.
- Docs: server/docs/configuration/environment-variables.md (`TRUST_PROXY_HEADERS`), web/docs/ops/ENVIRONMENT_VARIABLES.md
