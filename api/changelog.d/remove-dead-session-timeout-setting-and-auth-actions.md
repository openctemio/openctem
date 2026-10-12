### Removed: the unenforced organization session timeout and unused sign-in actions

- The organization security setting `session_timeout_min` is gone from the
  API and the web. It was validated, stored and audited but never enforced,
  so it promised a control that did not exist. Sessions follow the platform
  lifetimes (15-minute access token, 7-day idle refresh, 30-day session).
  A stored value is ignored. Upgrade in one step.
- Unused web server actions are removed: `getAccessToken` and
  `getLocalAccessToken` (they returned the httpOnly access token to their
  caller), the session list and revoke actions (the account page uses the
  API directly), the change-password action and the unused local
  current-user and refresh helpers. Every exported server action is a
  callable endpoint, so dead ones are attack surface.
