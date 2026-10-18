### Added: CAPTCHA, deployment region, storage quota, alert webhook and AI provider in the platform console

- Settings > CAPTCHA: the Turnstile site key and secret, set without a restart, with a "check the secret key" button. The secret is encrypted and never shown again; one CAPTCHA serves registration, request access and the tenant and console sign-ins.
- Settings > Configuration: the deployment region can be set once, while no organization exists, and never changes afterwards.
- Settings > Limits: the default storage quota per organization. New limit key `storage_mb` sets one organization's own quota on its Limits tab.
- Settings > Alerts: an HTTPS webhook that receives the administrator alerts (low disk, stale backups, expiring certificates, setting changes), optionally signed (`X-OpenCTEM-Signature`), with a "send a test alert" button.
- Settings > AI provider: the platform AI provider, model and key, off by default, with a "test the key" button.
- Changing the CAPTCHA, the region, the alert webhook or the AI provider needs a super admin, a fresh confirmation and a reason; it writes a critical admin audit row (never a secret) and tells every administrator.

### Behaviour change: environment values lock or default the moved settings

- `CAPTCHA_TURNSTILE_SECRET`/`_SITE_KEY`, `DEPLOYMENT_REGION` and any of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` still work and pin their setting: the console shows it as locked. `STORAGE_TENANT_QUOTA_MB` is the default until the console stores one.
- `SIGNUP_MODE=open` in production no longer refuses to start without CAPTCHA keys in the environment: open sign-up stays closed at runtime until a CAPTCHA is configured (or `SIGNUP_CAPTCHA=off-i-understand` is set).
- AI triage is always available for organizations that use their own key; a request in platform AI mode is refused with a clear message until a platform provider is on.
- **Upgrade note:** nothing to do. Existing environment values keep working; remove them to manage the settings in the console. No migration.

### Fixed: every new organization gets the deployment region

- Organizations created together with their owner (the console, self-service sign-up and approved access requests) were stored without the deployment region; only the other creation path stamped it. Existing organizations keep what they have (the region never changes after creation).
