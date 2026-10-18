### Fixed: operator-facing text follows the v0.11 console navigation

- Environment-variable descriptions, start-up and removed-variable messages, and the operator docs now name the console pages where they are (Settings > Sign-up, Limits, E-mail and CAPTCHA; Scanning > Platform scanning; Monitoring > Health and Software updates; Customers > Sign-ups; Security > Admin activity).
- `ADMIN_PUBLIC_URL` and `.env.example` show the console's default port 8443 (not 8444). `SELF_SERVICE_START_LIMITS` names `SIGNUP_MODE=open` instead of the removed `TENANT_CREATION_MODE`.
- `SIGNUP_CAPTCHA` is described as it behaves: open sign-up in production stays closed at runtime until a CAPTCHA is configured (Settings > CAPTCHA or the `CAPTCHA_TURNSTILE_*` keys), unless `SIGNUP_CAPTCHA=off-i-understand`.
- Scan refusal messages point to Scoping > Scope (the page that exists) instead of "Scoping > Targets" and "Scoping > Verified domains".
- `bootstrap-admin` prints the console's own address (`ADMIN_PUBLIC_URL`, or the default `https://<host>:8443` pattern) instead of the organization `/login` page.
- The console's approvals text lists deleting an organization among the actions that need a second super admin, and the access-requests hint says Settings > Sign-up (en and vi).
- Database roles doc: installations with `DB_ADMIN_USER` re-run the grant script after upgrading to v0.11.0 (new console table `admin_approvals`).
