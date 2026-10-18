### Security: platform console hardening (sessions, write-ahead audit, administrator accounts off the main site)

- An administrator may hold at most three verified console sessions; opening another ends the oldest (`console.session_evicted` in the administrators' audit log).
- A super administrator's write is recorded (`admin.write_started`, with the redacted request body) before it runs. If the audit log cannot be written the request is refused with 503 `AUDIT_UNAVAILABLE` and nothing changes.
- The audit redaction of request bodies also covers keys ending in `secret`, `password`, `_key` or `_token` (any case) and the keys `code`, `totp`, `recovery_code`, `recovery_codes`, including inside lists.
- The account of a platform administrator can no longer sign in on the tenant site (password, second factor, token exchange, social and SSO sign-in). The answer is the same as for a wrong password, with no session; the console's own sign-in is unchanged. The sign-in page tells administrators to use the admin console.
- The console's sign-in steps use their own page cookie `console_csrf` instead of the tenant site's `csrf_token`, so the two sites no longer overwrite each other's token on one host.
- The gateway's console site sends `Strict-Transport-Security` on proxied responses.
- Upgrade note: with `MANAGED_SERVICE=true` and `APP_ENV=production` the API now refuses to start unless `ADMIN_AUDIT_SINK` is set (an https, syslog+tls or file destination). Set it before upgrading a managed deployment; self-managed installations are unaffected.
