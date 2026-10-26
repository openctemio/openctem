### Added: social login (Google, GitHub, Microsoft) is configured in the platform console

- Settings > Social login: per provider the client ID, client secret (encrypted, write-only), scopes and "Offer on the sign-in page". The page shows the exact redirect URI to register, the impact on who can sign in, and "Test configuration" against the provider's token endpoint.
- Changes need a super admin, a fresh confirmation and a reason, are audited critical (never the secret) and apply on every replica without a restart. New setting key `auth.social_login`; no migration. `rekey` covers its secrets.
- **Upgrade note:** `OAUTH_<PROVIDER>_*` keep working as an override: while `OAUTH_<PROVIDER>_CLIENT_SECRET` is set, that provider is pinned and read-only in the console. Remove the variables to manage a provider in the console. `OAUTH_ENABLED=false` still switches all providers off; `OAUTH_STATE_SECRET` stays server-side.
