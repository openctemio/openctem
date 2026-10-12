### Behaviour change: platform e-mail is set in the admin console

- The platform's SMTP server is set in the admin console, System > E-mail (`GET`/`PUT /api/v1/admin/settings/email`, super admin with a fresh authenticator code, audited without the password). The password is encrypted with `APP_ENCRYPTION_KEY` and never returned. "Send a test e-mail" sends to the acting administrator's own address only. A change applies without a restart.
- **Removed:** `SMTP_ENABLED`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_FROM_NAME`, `SMTP_TLS`, `SMTP_SKIP_VERIFY`, `SMTP_TIMEOUT`. Startup refuses them with a hint. `SMTP_BASE_URL` (the link base) stays.
- Headless installs: `bootstrap-admin` stores `BOOTSTRAP_SMTP_HOST` (with `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_FROM_NAME`, `_STARTTLS`) as the platform e-mail setting when none is stored.
- **Upgrade note:** before upgrading, note your SMTP settings, remove the `SMTP_*` lines (except `SMTP_BASE_URL`), and enter the settings in the admin console after the upgrade (or run `bootstrap-admin` with `BOOTSTRAP_SMTP_*`).
