### Security: SIGNUP_MODE is a sign-up ceiling the admin console cannot exceed

- New `SIGNUP_MODE` in the server environment: `disabled` (default), `domain` or `open`. The
  console sign-up policy (System > Sign-up) is now a runtime switch below it: the policy in force is
  the stored policy clamped to the ceiling, and saving `self_service` under `disabled` or `domain`
  answers 409 `SIGNUP_LOCKED_BY_DEPLOYMENT` before the authenticator code is checked. A stolen
  console session can no longer open registration on a closed deployment. `GET
  /api/v1/admin/settings/signup` also reports `deployment_mode`, `self_service_locked` and
  `effective_mode`; the console shows the lock and its reason (en, vi).
- Start-up refuses to run when `SIGNUP_MODE` is `domain` or `open` without the platform e-mail
  (System > E-mail) or without local accounts, and when `SIGNUP_MODE=open` runs in production
  without `CAPTCHA_TURNSTILE_SECRET`/`CAPTCHA_TURNSTILE_SITE_KEY` (or `SIGNUP_CAPTCHA=off-i-understand`).
  While running, public sign-up closes whenever the platform e-mail stops working.

### Removed: TENANT_CREATION_MODE

- Replaced by `SIGNUP_MODE`. Start-up refuses to run while `TENANT_CREATION_MODE` is set.
- **Upgrade note:** remove `TENANT_CREATION_MODE` from the environment. `admin_only` (the old
  default) is `SIGNUP_MODE=disabled`, the new default, so nothing else is needed. `self_service` is
  `SIGNUP_MODE=open`, which also needs the platform e-mail set before start (`bootstrap-admin`
  `BOOTSTRAP_SMTP_*`, or start once with `disabled` and set it in System > E-mail) and, in
  production, the Turnstile keys. A stored `self_service` policy on a deployment that moves to
  `disabled` is clamped to `admin_only`; existing users, organizations and sessions are not affected.
