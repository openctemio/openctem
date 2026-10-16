# Environment variable reference

<!-- GENERATED from api/internal/config/env_registry.yaml by "make env-docs". Do not edit. -->

Every environment variable OpenCTEM reads. **Default** is the value used when the
variable is unset or empty (durations in Go syntax: `30s`, `5m`, `24h`; lists
comma-separated). **Required**: `yes` means it must be set; `production` means
production (`APP_ENV` unset or `production`) refuses to start without a valid value.
**Secret** values belong in a secret store, never in version control or logs.

Settings an administrator changes at run time (sign-up policy, plans, scan
approval, AI applications, ...) are not environment variables: they live in the
admin console and the organization settings.

## API server

Read by the API server at start-up (`server`). The server refuses to start when a variable under one of its prefixes is a likely misspelling of a listed name, or when a typed value does not parse; `server -check-config` runs the same checks without starting.

Prefixes the API owns: `APP_`, `BRAND_`, `SERVER_`, `DB_`, `REDIS_`, `LOG_`, `AUTH_`, `SSO_`, `OAUTH_`, `KEYCLOAK_`, `CORS_`, `RATE_LIMIT_`, `SMTP_`, `STORAGE_`, `SENSOR_`, `INGEST_`, `SCOPE_`, `CERT_MONITOR_`, `EASM_`, `ASSET_`, `ADMIN_AUDIT_`, `ADMIN_SESSION_`, `AUDIT_`, `METRICS_`, `MCP_`, `AI_`, `WORKER_`, `PROGRAMFEED_`, `VULNFEED_`, `CAPTCHA_`, `SIGNER_`, `OPENCTEM_HTTPSEC_`, `TENANT_`, `INVITATION_`, `VERSION_CHECK_`.

### Application

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `APP_ENV` | string | `production` |  |  | Environment name. `production` (also when unset) turns on the production checks (TLS to PostgreSQL and Redis, strong secrets, rate limiting, secure cookies; `server -check-config` reports them). Any value other than `development` requires `APP_ENCRYPTION_KEY`, refuses the published development secrets and defaults `AUTH_COOKIE_SECURE` to `true`. Set `development` explicitly for a local or trial setup without TLS to the datastores. Up to v0.8.0 an unset value meant `development`. |
| `APP_NAME` | string | `openctem` |  |  | Technical name of the service in logs. The product name users see is `BRAND_NAME`. |
| `APP_URL` | string | empty |  |  | Public origin of the platform (`https://ctem.example.com`): the one URL browsers, sensors and e-mail links use. Set it in every deployment. When set, it is the default of `CORS_ALLOWED_ORIGINS`, `SMTP_BASE_URL` and `OAUTH_FRONTEND_CALLBACK_URL`, and SAML service-provider URLs and the sensor endpoint are built from it. Must be an http(s) URL without credentials, query or fragment. |
| `DEPLOYMENT_REGION` | string | empty |  |  | Data region of this deployment (1-32 lowercase letters, digits or hyphens, e.g. `eu-central`). Every organization created here gets it, it is shown in the console and never changes. Unset: not named. |

### Brand

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `BRAND_FILE` | path | empty |  |  | Optional YAML file with the brand settings (`name`, `short_name`, `primary_color`, `docs_url`, `website_url`, `support_url`, `support_email`, `terms_url`, `privacy_url`, `email_footer`, `powered_by`, `logo_light_file`, `logo_dark_file`, `favicon_file`; image paths relative to the file). A `BRAND_*` variable wins over the file. See `docs/architecture/brand.md`. |
| `BRAND_NAME` | string | empty |  |  | Default `OpenCTEM`. Product name shown in the console, emails, reports and notifications (at most 64 characters; no markup characters). |
| `BRAND_SHORT_NAME` | string | empty |  |  | Short product name for narrow places (the sidebar, the browser tab). Defaults to `BRAND_NAME`. |
| `BRAND_PRIMARY_COLOR` | string | empty |  |  | Primary color as `#rrggbb`. Unset keeps the theme color. |
| `BRAND_DOCS_URL` | string | empty |  |  | Default `https://docs.openctem.io`. Documentation site (https). Documentation links in the console and API messages keep their path on this origin. |
| `BRAND_WEBSITE_URL` | string | empty |  |  | Default `https://openctem.io`. Product website (https). |
| `BRAND_SUPPORT_URL` | string | empty |  |  | Support page (https). Unset hides the support link. |
| `BRAND_SUPPORT_EMAIL` | string | empty |  |  | Default `info@openctem.io`. Support email address. |
| `BRAND_TERMS_URL` | string | empty |  |  | Terms of service (https). The admin console legal settings win when set there. |
| `BRAND_PRIVACY_URL` | string | empty |  |  | Privacy policy (https). The admin console legal settings win when set there. |
| `BRAND_EMAIL_FOOTER` | string | empty |  |  | Plain-text line added to the footer of every email (at most 500 characters). |
| `BRAND_POWERED_BY` | bool | `true` |  |  | Show a "Powered by OpenCTEM" credit next to a brand other than OpenCTEM. |
| `BRAND_LOGO_LIGHT_FILE` | path | empty |  |  | Logo for light backgrounds: PNG, JPEG, WebP or SVG, at most 512 KiB. SVG is reduced to drawing elements; a file with script, external references or event handlers is refused at startup. Unset keeps the built-in logo. |
| `BRAND_LOGO_DARK_FILE` | path | empty |  |  | Logo for dark backgrounds (same rules as `BRAND_LOGO_LIGHT_FILE`). Unset uses the light logo. |
| `BRAND_FAVICON_FILE` | path | empty |  |  | Browser tab icon: PNG, ICO or SVG, at most 512 KiB. Unset keeps the built-in icon. |

### HTTP server

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `MAX_CONCURRENT_REQUESTS` | int | `1000` |  |  | Maximum number of requests the API handles at once; further requests are refused. |
| `SERVER_HOST` | string | `0.0.0.0` |  |  | Listen address of the API. |
| `SERVER_MAX_BODY_SIZE` | int | `10485760` |  |  | Default request body limit in bytes. Some routes (for example asset import) set their own, larger limit. |
| `SERVER_PORT` | int | `8080` |  |  | Listen port of the API (REST, WebSocket, `/health`, `/ready`, `/metrics`). |
| `SERVER_READ_TIMEOUT` | duration | `15s` |  |  | HTTP server read timeout (Go duration). |
| `SERVER_REQUEST_TIMEOUT` | duration | `30s` |  |  | Per-request handler timeout. |
| `SERVER_SHUTDOWN_TIMEOUT` | duration | `30s` |  |  | Grace period for in-flight requests on shutdown. |
| `SERVER_TRUSTED_PROXIES` | list | empty |  |  | Comma-separated CIDRs or IPs of proxies whose `X-Real-IP` / `X-Forwarded-For` the API believes (audit log, rate limits, IP allowlists). Empty: the API treats every peer as the client. The Compose stack lists the gateway and the web console. |
| `SERVER_WRITE_TIMEOUT` | duration | `15s` |  |  | HTTP server write timeout. |
| `SESSION_TIMEOUT_MINUTES` | int | `30` |  |  | Maximum age, in minutes, of an access token (from its issued-at time) before the API answers `401 Session has expired`. `0` turns the check off. |
| `SERVER_TLS_CERT_FILE` | path | empty |  |  | PEM certificate (full chain) for the API listener to terminate TLS itself, when no TLS proxy is in front. Set together with `SERVER_TLS_KEY_FILE`. |
| `SERVER_TLS_KEY_FILE` | path | empty |  |  | PEM key matching `SERVER_TLS_CERT_FILE`. |

### Database (PostgreSQL)

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `DB_CONN_MAX_LIFETIME` | duration | `5m` |  |  | Maximum lifetime of a pooled connection. |
| `DB_HOST` | string | `localhost` | yes |  | PostgreSQL host. |
| `DB_JIT_ENABLED` | bool | `false` |  |  | PostgreSQL JIT for the API's sessions. Off by default because request-path queries pay the JIT compile cost without benefiting from it. |
| `DB_MAX_IDLE_CONNS` | int | `5` |  |  | Maximum idle connections kept in the pool. |
| `DB_MAX_OPEN_CONNS` | int | `25` |  |  | Maximum open connections in the API's pool. |
| `DB_NAME` | string | `openctem` |  |  | Database name. |
| `DB_PASSWORD` | string | empty | yes | yes | Password of `DB_USER`. Required outside `APP_ENV=development`; there is no default. |
| `DB_PORT` | int | `5432` |  |  | PostgreSQL port. |
| `DB_SSLMODE` | string | `disable` | production |  | libpq `sslmode`. Production refuses `disable`: use `require`, `verify-ca` or `verify-full`. |
| `DB_USER` | string | `openctem` | yes |  | Role the API connects as. With the least-privilege layout this is the DML-only role (`openctem_app`). |
| `MIGRATIONS_DIR` | string | `migrations` |  |  | Directory the start-up schema check reads the shipped migrations from. The images set the right path; change it only for a custom layout. |
| `SKIP_SCHEMA_CHECK` | string | `unset` |  |  | `true` skips the start-up check that refuses to start when the database schema is behind the binary or dirty. Keep it unset in production. |

### Redis

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `REDIS_DB` | int | `0` |  |  | Redis database number. |
| `REDIS_DIAL_TIMEOUT` | duration | `5s` |  |  | Connect timeout. Production requires at least `1s`. |
| `REDIS_HOST` | string | `localhost` | yes |  | Redis host. |
| `REDIS_MAX_RETRIES` | int | `3` |  |  | Retries per command. Production requires 1 to 10. |
| `REDIS_MAX_RETRY_DELAY` | duration | `3s` |  |  | Maximum back-off between retries. |
| `REDIS_MIN_IDLE_CONNS` | int | `2` |  |  | Minimum idle connections. |
| `REDIS_MIN_RETRY_DELAY` | duration | `100ms` |  |  | Minimum back-off between retries. |
| `REDIS_PASSWORD` | string | empty | production | yes | Redis password. Production requires at least 32 characters. |
| `REDIS_POOL_SIZE` | int | `10` |  |  | Connection pool size. Production requires 10 to 500. |
| `REDIS_PORT` | int | `6379` |  |  | Redis port. |
| `REDIS_READ_TIMEOUT` | duration | `3s` |  |  | Read timeout. Production requires at least `1s`. |
| `REDIS_TLS_CA_FILE` | string | empty |  |  | CA certificate (PEM) to verify Redis with, when its certificate is not publicly trusted. |
| `REDIS_TLS_CERT_FILE` | string | empty |  |  | Client certificate (PEM) for mutual TLS. |
| `REDIS_TLS_ENABLED` | bool | `false` | production |  | Connect to Redis over TLS. Required in production. |
| `REDIS_TLS_KEY_FILE` | string | empty |  |  | Client private key (PEM) for mutual TLS. |
| `REDIS_TLS_SKIP_VERIFY` | bool | `false` |  |  | Skip certificate verification. Production refuses `true`. |
| `REDIS_WRITE_TIMEOUT` | duration | `3s` |  |  | Write timeout. Production requires at least `1s`. |

### Logging

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `LOG_ERROR_SAMPLING_RATE` | float | `1.0` |  |  | Fraction (0.0 to 1.0) of error records kept above the threshold. |
| `LOG_FORMAT` | string | `json` |  |  | `json` or `text`. |
| `LOG_LEVEL` | string | `info` |  |  | `debug`, `info`, `warn` or `error`. Production refuses `debug`. |
| `LOG_SAMPLING_ENABLED` | bool | `false` |  |  | Sample repeated log records (same level and message) to bound log volume. |
| `LOG_SAMPLING_RATE` | float | `0.1` |  |  | Fraction (0.0 to 1.0) of records kept above the threshold. |
| `LOG_SAMPLING_THRESHOLD` | int | `100` |  |  | Identical records per second always written before sampling starts. |
| `LOG_SLOW_REQUEST_SECONDS` | int | `5` |  |  | A request slower than this is logged at WARN as `slow http request`. `0` turns it off. |

### Encryption keys

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `APP_ENCRYPTION_KEY` | string | empty | yes | yes | AES-256-GCM key for stored credentials (integration tokens, SMTP passwords, identity-provider secrets). 32 raw, 64 hex or 44 base64 characters: `openssl rand -hex 32`. Required unless `APP_ENV=development`. Back it up with the database: without it the stored credentials cannot be decrypted. |
| `APP_ENCRYPTION_KEY_FORMAT` | string | empty |  |  | `raw`, `hex` or `base64`. Detected from the key length when unset. |
| `APP_ENCRYPTION_KEY_PREVIOUS` | list | empty |  | yes | Comma-separated earlier keys, only while a key rotation is in progress. Values encrypted under them stay readable. Remove them when the rotation is finished. |
| `APP_TEMPLATE_SIGNING_KEY` | string | empty |  | yes | Master secret the per-organization signing keys of custom scanner templates are derived from. Same formats as `APP_ENCRYPTION_KEY` and must differ from it. Set it to rotate template keys independently of the encryption key. Unset: derived from `APP_ENCRYPTION_KEY`. |
| `APP_CONTENT_SIGNING_KEY` | string | empty |  | yes | Master secret of each organization's content pack signing key (Ed25519). Same formats as `APP_ENCRYPTION_KEY` and must differ from it and from `APP_TEMPLATE_SIGNING_KEY`. Unset: derived from `APP_ENCRYPTION_KEY` under its own label. |
| `FINGERPRINT_KEY` | string | empty | production | yes | Server secret the fingerprint of each reported secret finding is keyed from (and the key CI jobs hash raw secrets with). At least 32 characters: `openssl rand -hex 32`. Never rotate it with `APP_ENCRYPTION_KEY`: changing it changes every secret's identity, so a secret seen again opens a second finding. On an install that already stores secret findings, set it to the current `APP_ENCRYPTION_KEY` value (the key those fingerprints were made with). Required unless `APP_ENV=development`, where `APP_ENCRYPTION_KEY` is used when it is unset. Back it up with the database. |
| `CONTENT_TRUST_ROOT_KEY_IDS` | list | empty |  |  | Extra content catalog roots (comma-separated key ids, `SHA256:<hex>`) trusted beside the roots pinned in the release, for an operator's own catalog source (RFC-099). Setting it writes a high-severity admin audit row at startup. Unset: only the pinned roots; with none, bundle imports are refused. |
| `CONTENT_SIGSTORE_TRUSTED_ROOT` | path | empty |  |  | Path of a Sigstore trusted root (JSON) that replaces the one embedded in the release for verifying publisher signatures of content packages (RFC-099). Setting it writes a high-severity admin audit row with the file's SHA-256 at startup. Unset: the embedded trusted root. |

### Authentication

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `AUTH_ACCESS_TOKEN_DURATION` | duration | `15m` |  |  | Access token lifetime. |
| `AUTH_COOKIE_DOMAIN` | string | empty |  |  | `Domain` attribute of session cookies. Unset: the current host only. |
| `AUTH_COOKIE_SAMESITE` | string | `lax` |  |  | `strict`, `lax` or `none` (`none` needs `AUTH_COOKIE_SECURE=true`). |
| `AUTH_COOKIE_SECURE` | bool | `true` | production |  | `Secure` flag on session cookies. Must be `true` in production. |
| `AUTH_EMAIL_VERIFICATION_DURATION` | duration | `24h` |  |  | Lifetime of an email verification link. |
| `AUTH_JWT_ISSUER` | string | `api` |  |  | `iss` claim of issued tokens. |
| `AUTH_JWT_SECRET` | string | empty |  | yes | HMAC secret that signs session tokens. Unset: derived from `APP_ENCRYPTION_KEY` (HKDF, 64 bytes), so rotating the encryption key also signs every user out; set it (at least 64 characters in production: `openssl rand -hex 64`) to rotate the two independently. Changing it signs every user out. |
| `AUTH_LOCKOUT_DURATION` | duration | `15m` |  |  | How long a locked account stays locked. |
| `AUTH_MAX_ACTIVE_SESSIONS` | int | `10` |  |  | Concurrent sessions per user. |
| `AUTH_MAX_LOGIN_ATTEMPTS` | int | `5` |  |  | Failed sign-ins before the account is locked. |
| `AUTH_PASSWORD_MIN_LENGTH` | int | `12` |  |  | Minimum password length. At least 6; at least 8 in production. |
| `AUTH_PASSWORD_REQUIRE_LOWERCASE` | bool | `true` |  |  | Require a lowercase letter. |
| `AUTH_PASSWORD_REQUIRE_NUMBER` | bool | `true` |  |  | Require a digit. |
| `AUTH_PASSWORD_REQUIRE_SPECIAL` | bool | `false` |  |  | Require a special character. |
| `AUTH_PASSWORD_REQUIRE_UPPERCASE` | bool | `true` |  |  | Require an uppercase letter. |
| `AUTH_PASSWORD_RESET_DURATION` | duration | `1h` |  |  | Lifetime of a password reset link. |
| `AUTH_PROVIDER` | string | `local` |  |  | `local` (built-in email and password), `oidc` (an external Keycloak realm) or `hybrid` (both). Up to v0.8.0 the default was `oidc`: an installation that relied on that must now set `AUTH_PROVIDER=oidc`. |
| `AUTH_REFRESH_TOKEN_DURATION` | duration | `168h` |  |  | Refresh token lifetime (7 days). |
| `AUTH_REQUIRE_EMAIL_VERIFICATION` | bool | `true` |  |  | Require a verified email address. Production refuses `false` with `local` or `hybrid`. |
| `AUTH_SESSION_DURATION` | duration | `720h` |  |  | Session lifetime (30 days). |

### Organizations and scope guardrails

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `SCOPE_DENY_EXTRA` | list | empty |  |  | Comma-separated domains and CIDRs that no organization may target, in addition to the built-in deny list (for example the platform's own names and ranges). |
| `SCOPE_PUBLIC_CODE_HOSTS_EXTRA` | list | empty |  |  | Comma-separated code hosts shared by many organizations, in addition to the built-in list (github.com, gitlab.com, bitbucket.org and others). A repository scope entry on such a host must name a namespace (host/namespace/*), never the whole host. |
| `SCOPE_MAX_PUBLIC_CIDR_V4` | int | `16` |  |  | Largest public IPv4 range (prefix length) one scope entry may cover. Private ranges are not capped. |
| `SCOPE_MAX_PUBLIC_CIDR_V6` | int | `32` |  |  | Largest public IPv6 range one scope entry may cover. |
| `SIGNUP_MODE` | string | `disabled` |  |  | The deployment's sign-up ceiling; no API can change it, and the console sign-up policy can only stay at or below it. `disabled`: no public account creation; people get accounts from a platform administrator, an invitation or their organization's SSO, and only a platform administrator creates organizations. `domain`: public sign-up only for addresses on an organization's verified domain, who join that organization (never create one). `open`: anyone may sign up and create an organization (the hosted service). `domain` and `open` need the platform e-mail (System > E-mail) at start and verify every self-registered address; `open` in production also needs the Turnstile keys or `SIGNUP_CAPTCHA`. Any other value stops start-up. Replaces `TENANT_CREATION_MODE`. |
| `SIGNUP_CAPTCHA` | string | empty |  |  | Only value: `off-i-understand`, which accepts `SIGNUP_MODE=open` in production without a CAPTCHA (labs, training installs). Unset: open sign-up in production refuses to start without `CAPTCHA_TURNSTILE_SECRET` and `CAPTCHA_TURNSTILE_SITE_KEY`. |
| `CAPTCHA_TURNSTILE_SECRET` | string | empty |  | yes | Cloudflare Turnstile secret for the public request-access form. Unset: no CAPTCHA (the rate limits still apply). Set together with `CAPTCHA_TURNSTILE_SITE_KEY`. |
| `CAPTCHA_TURNSTILE_SITE_KEY` | string | empty |  |  | Cloudflare Turnstile site key (public) shown on the request-access form. Set together with `CAPTCHA_TURNSTILE_SECRET`. |

### Single sign-on and social login

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `KEYCLOAK_BASE_URL` | string | `http://localhost:8080` |  |  | Keycloak server for `AUTH_PROVIDER=oidc` or `hybrid`. In production it must be set, use HTTPS and differ from the default. |
| `KEYCLOAK_CLIENT_ID` | string | empty |  |  | Expected audience of Keycloak tokens (optional). |
| `KEYCLOAK_HTTP_TIMEOUT` | duration | `10s` |  |  | Timeout of requests to Keycloak. |
| `KEYCLOAK_JWKS_REFRESH_INTERVAL` | duration | `1h` |  |  | How often Keycloak's signing keys are refreshed. |
| `KEYCLOAK_REALM` | string | `openctem` |  |  | Keycloak realm. In production with `oidc` or `hybrid` it must be set to a value other than the default. |
| `OAUTH_ENABLED` | bool | `true` |  |  | Master switch for social login (Google, GitHub, Microsoft). A provider is offered only when its own `*_ENABLED`, client ID and secret are set. |
| `OAUTH_FRONTEND_CALLBACK_URL` | string | `APP_URL/auth/callback, else http://localhost:3000/auth/callback` |  |  | Web console URL the social-login and SSO flows return to. Set it only when the console is not at `APP_URL`. |
| `OAUTH_GITHUB_CLIENT_ID` | string | empty |  |  | GitHub OAuth client ID. |
| `OAUTH_GITHUB_CLIENT_SECRET` | string | empty |  | yes | GitHub OAuth client secret. |
| `OAUTH_GITHUB_ENABLED` | bool | `false` |  |  | Offer GitHub sign-in. |
| `OAUTH_GITHUB_SCOPES` | list | `read:user,user:email` |  |  | Requested scopes. |
| `OAUTH_GOOGLE_CLIENT_ID` | string | empty |  |  | Google OAuth client ID. |
| `OAUTH_GOOGLE_CLIENT_SECRET` | string | empty |  | yes | Google OAuth client secret. |
| `OAUTH_GOOGLE_ENABLED` | bool | `false` |  |  | Offer Google sign-in. |
| `OAUTH_GOOGLE_SCOPES` | list | `openid,email,profile` |  |  | Requested scopes. |
| `OAUTH_MICROSOFT_CLIENT_ID` | string | empty |  |  | Microsoft OAuth client ID. |
| `OAUTH_MICROSOFT_CLIENT_SECRET` | string | empty |  | yes | Microsoft OAuth client secret. |
| `OAUTH_MICROSOFT_ENABLED` | bool | `false` |  |  | Offer Microsoft sign-in. |
| `OAUTH_MICROSOFT_SCOPES` | list | `openid,email,profile,User.Read` |  |  | Requested scopes. |
| `OAUTH_STATE_DURATION` | duration | `10m` |  |  | Lifetime of an OAuth `state` token. |
| `OAUTH_STATE_SECRET` | string | empty |  | yes | Secret that signs the OAuth `state` parameter. Unset: derived from the session secret under its own label. |
| `SSO_ALLOWED_REDIRECT_URIS` | list | `derived` |  |  | Comma-separated exact-match allow-list for the `redirect_uri` of the per-organization SSO flow: origins (`https://ctem.example.com`) or origin-plus-path prefixes ending in `/`. Unset: derived from `CORS_ALLOWED_ORIGINS`, `OAUTH_FRONTEND_CALLBACK_URL` and `SMTP_BASE_URL`. |
| `SSO_ENTRA_ALLOWED_DOMAINS` | list | `empty (any)` |  |  | Comma-separated email domains the fallback accepts. |
| `SSO_ENTRA_ALLOWED_TENANTS` | list | `empty (none)` |  |  | Comma-separated organization slugs allowed to use the fallback. Empty disables it for every organization. |
| `SSO_ENTRA_AUTO_PROVISION` | bool | `true` |  |  | Create accounts on first sign-in through the fallback. |
| `SSO_ENTRA_CLIENT_ID` | string | empty |  |  | Application (client) ID of the fallback app registration. |
| `SSO_ENTRA_CLIENT_SECRET` | string | empty |  | yes | Client secret of the fallback app registration. |
| `SSO_ENTRA_DEFAULT_ROLE` | string | `viewer` |  |  | Role given to users the fallback provisions. |
| `SSO_ENTRA_DISPLAY_NAME` | string | `Microsoft Entra ID` |  |  | Button label of the fallback. |
| `SSO_ENTRA_ENABLED` | bool | `false` |  |  | Platform-wide Microsoft Entra ID fallback, used by an organization that has no Entra ID provider of its own and is listed in `SSO_ENTRA_ALLOWED_TENANTS`. Organization SSO is normally configured per organization in the console. |
| `SSO_ENTRA_TENANT_ID` | string | `common` |  |  | Entra directory ID of the fallback. |
| `MCP_OAUTH_DCR_ENABLED` | bool | `false` |  |  | Turns on OAuth dynamic client registration (`POST /oauth/register`, RFC 7591) for MCP clients. Such clients are always shown as unverified. |
| `MCP_OAUTH_TRUSTED_CLIENT_HOSTS` | list | empty |  |  | Comma-separated hosts whose MCP client ID metadata documents every organization treats as verified. Organizations add their own on top. |

### CORS and rate limiting

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `CORS_ALLOWED_HEADERS` | list | `Accept,Authorization,Content-Type,X-Request-ID` |  |  | Allowed request headers. |
| `CORS_ALLOWED_METHODS` | list | `GET,POST,PUT,DELETE,OPTIONS,PATCH` |  |  | Allowed methods. |
| `CORS_ALLOWED_ORIGINS` | list | `APP_URL origin, else http://localhost:3000` |  |  | Comma-separated browser origins allowed to call the API; the WebSocket `Origin` is checked against it too. Set it only when the console runs on another origin than `APP_URL`. Production refuses `*`. |
| `CORS_MAX_AGE` | int | `86400` |  |  | Preflight cache lifetime in seconds. |
| `RATE_LIMIT_BURST` | int | `200` |  |  | Burst size per client. |
| `RATE_LIMIT_CLEANUP` | duration | `1m` |  |  | How often idle limiter entries are removed. |
| `RATE_LIMIT_ENABLED` | bool | `true` |  |  | Global per-client rate limiter. Production refuses `false`. |
| `RATE_LIMIT_READ_PER_MIN` | int | `120` |  |  | Per-user budget (and burst) for authenticated `GET` requests. Values of 0 or less fall back to the default. |
| `RATE_LIMIT_RPS` | float | `100` |  |  | Requests per second per client. |

### Email (SMTP)

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `SMTP_BASE_URL` | string | `APP_URL, else http://localhost:3000` |  |  | Base URL of links in e-mails. Set it only when the console is not at `APP_URL`. |

### Attachment storage

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `STORAGE_ACCESS_KEY` | string | empty |  | yes | Access key. Required with `s3` / `minio`. |
| `STORAGE_BUCKET` | string | empty |  |  | Bucket for `s3` / `minio`. Required with those providers. |
| `STORAGE_CLAMD_ADDRESS` | string | empty |  |  | ClamAV daemon (`host:port` or `unix:/path`, e.g. `clamav:3310` with `docker-compose.clamav.yml`) that scans new uploads. A flagged file is kept and marked, audited `attachment.malware_detected`, and downloads only after a confirmation. Unset: no scanning. |
| `STORAGE_DIRECT_DOWNLOAD` | bool | `false` |  |  | Hand out 60-second signed URLs (`GET /api/v1/attachments/{id}/signed-url`) for files in an HTTPS bucket, after the same checks as a download through the API; the console uses them for file downloads. Files on local storage, in a plain-HTTP bucket and flagged files always download through the API. The bucket needs CORS only for downloads started with `fetch`. |
| `STORAGE_ENDPOINT` | string | empty |  |  | Endpoint of an S3-compatible store, for example MinIO. Unset: AWS S3. |
| `STORAGE_LOCAL_PATH` | string | `./data/attachments` |  |  | Directory for `local` storage, relative to the working directory (`/app` in the API image, so `/app/data/attachments`). Put it on a persistent volume and back it up. |
| `STORAGE_SSE` | string | empty |  |  | Server-side encryption asked for on every object written to the server bucket: `AES256` or `aws:kms`. Unset: the bucket's default encryption. Only with `s3` / `minio`. |
| `STORAGE_SSE_KMS_KEY_ID` | string | empty |  |  | KMS key (id or ARN) for `STORAGE_SSE=aws:kms`. Unset: the bucket's default KMS key. |
| `STORAGE_TENANT_QUOTA_MB` | int | `20480` |  |  | Most attachment bytes one organization may hold, in MiB (20480 = 20 GiB). An upload that would pass it is refused with 413 `STORAGE_QUOTA_EXCEEDED`. 0 = no quota. |
| `STORAGE_ORPHAN_GRACE_DAYS` | int | `7` |  |  | Days evidence files stay after their finding or campaign is deleted; then the retention sweep deletes them (audited `attachment.purged`). 0 = keep them. |
| `STORAGE_UNLINKED_RETENTION_HOURS` | int | `24` |  |  | Hours an upload never linked to a finding or campaign stays before the retention sweep deletes it. Authorization letter files are never purged. 0 = keep them. |
| `STORAGE_PROVIDER` | string | `local` |  |  | `local`, `s3` or `minio`. Any other value stops start-up. |
| `STORAGE_REGION` | string | empty |  |  | Bucket region. |
| `STORAGE_SECRET_KEY` | string | empty |  | yes | Secret key. Required with `s3` / `minio`. |

### Sensors

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `SENSOR_CA_CERT_FILE` | string | empty |  |  | Private CA certificate (PEM) the install snippets install on the sensor host. Set it with the gateway in TLS mode `internal` (the Compose stack points it at the exported root CA). |
| `CI_RUNNER_LATEST_VERSION` | string | `versions.yaml` ci.latest, built into the API |  |  | Newest CI runner release (openctemio/ci: the openctem-ci action and image). The console's pipeline snippets pin it, and a pipeline on an older runner shows an update. CI runners have their own release line; the sensor settings never apply to them. `none` or `off` turns the comparison off. |
| `CI_RUNNER_MIN_VERSION` | string | `versions.yaml` ci.min, built into the API |  |  | Oldest accepted CI runner release. The token exchange refuses an older runner (`RUNNER_OUTDATED`) and its pipeline is shown as degraded. Empty, `none` or `off`: no minimum. |
| `SENSOR_COMMAND_LEASE` | duration | `3m` |  |  | How long a sensor holds a claimed task without renewing it; an expired lease puts the task back in the queue. |
| `SENSOR_CONFIG_TEMPLATES_DIR` | string | `configs/sensor-products` |  |  | Directory of the sensor install snippet templates shown in the console: one directory per snippet set (<set>/<format>.tmpl). A sensor product of your own adds a directory here. |
| `SENSOR_PRODUCTS_FILE` | string | empty |  |  | File of extra sensor products (for example your own sensor built on the SDK), in the versions.yaml product format; added to the built-in catalog. An invalid file stops the API from starting. |
| `SENSOR_HEALTH_SLOW_HEARTBEAT` | duration | `2s` |  |  | Heartbeat handling p95 that counts as slow. While the platform is slow, no sensor is marked offline. |
| `SENSOR_HEALTH_STARTUP_GRACE` | duration | `0` |  |  | Time after API start during which no sensor is marked offline. |
| `SENSOR_HEARTBEAT_BUSY_INTERVAL` | duration | `5s` |  |  | Interval advised while work is waiting for the sensor. |
| `SENSOR_HEARTBEAT_INTERVAL` | duration | `30s` |  |  | Heartbeat interval advised to an idle sensor. |
| `SENSOR_HEARTBEAT_MAX_INTERVAL` | duration | `5m` |  |  | Upper clamp of every advised interval (also capped at half of `WORKER_HEARTBEAT_TIMEOUT`). |
| `SENSOR_HEARTBEAT_MIN_INTERVAL` | duration | `5s` |  |  | Lower clamp of every advised interval. |
| `SENSOR_HEARTBEAT_SLOW_QUERY` | duration | `250ms` |  |  | Heartbeat query latency that counts as "platform under load". |
| `SENSOR_COLLECTOR_IMAGE` | string | `ghcr.io/openctemio/asset-collector:latest` |  |  | Image, with its tag, the install snippets of a collector sensor run (the asset collector, not the scanner). Pin a collector release here. |
| `SENSOR_IMAGE` | string | the scanning sensor image in `versions.yaml` (ghcr.io/openctemio/sensor) |  |  | Image repository the scanning sensor's install snippets run, for a mirror. The tag is the sensor's latest release in `versions.yaml`, never `latest`. Other sensor products always use their published image. |
| `SENSOR_KEY_PEPPER` | string | empty |  | yes | Secret the sensor API-key hashes are keyed with. At least 32 characters when set. Unset: derived from `APP_ENCRYPTION_KEY`. |
| `SENSOR_KEY_PEPPER_PREVIOUS` | list | empty |  | yes | Comma-separated earlier peppers, kept while keys move to a new `SENSOR_KEY_PEPPER`. |
| `SENSOR_KEY_RENEW_BEFORE` | duration | empty |  |  | How long before expiry the heartbeat asks the sensor to rotate its key. Unset: half of `SENSOR_KEY_TTL` (24h without a TTL). |
| `SENSOR_KEY_RENEW_GRACE` | duration | `15m` |  |  | How long the key a sensor renewed with keeps working after the renewal. `0` retires it at once. |
| `SENSOR_KEY_TTL` | duration | `2160h` |  |  | Validity of a sensor API key renewed by the sensor itself. `0`: renewed keys never expire. Keys created or regenerated by an administrator never expire. |
| `SENSOR_LB_CPU_WEIGHT` | float | `0.40` |  |  | Weight of CPU usage. |
| `SENSOR_LB_DISK_IO_WEIGHT` | float | `0.10` |  |  | Weight of disk I/O. |
| `SENSOR_LB_JOB_WEIGHT` | float | `0.30` |  |  | Weight of the job load in the sensor load score used to place work (weights should sum to 1.0). |
| `SENSOR_LB_MAX_DISK_THROUGHPUT_MBPS` | float | `500` |  |  | Disk throughput (MB/s) that counts as 100% disk load. |
| `SENSOR_LB_MAX_NETWORK_THROUGHPUT_MBPS` | float | `1000` |  |  | Network throughput (MB/s) that counts as 100% network load. |
| `SENSOR_LB_MEMORY_WEIGHT` | float | `0.15` |  |  | Weight of memory usage. |
| `SENSOR_LB_NETWORK_WEIGHT` | float | `0.05` |  |  | Weight of network I/O. |
| `SENSOR_PUBLIC_API_URL` | string | empty |  |  | URL sensors connect to, embedded in the install snippets and configuration templates. Unset: `APP_URL`. |
| `SENSOR_SLIM_HEARTBEAT` | bool | `true` |  |  | Let sensors with an acknowledged manifest leave their tool inventory out of heartbeats. `false` asks every sensor for full heartbeats. |
| `WORKER_HEALTH_CHECK_ENABLED` | bool | `false` |  |  | Legacy sensor health checker. Keep it off: the sensor health controller owns liveness and the legacy checker marks every sensor offline right after an API restart. |
| `WORKER_HEALTH_CHECK_INTERVAL` | duration | `1m` |  |  | Interval of the legacy checker. |
| `WORKER_HEARTBEAT_TIMEOUT` | duration | `5m` |  |  | No heartbeat for this long marks a sensor inactive. Advised heartbeat intervals stay below half of it. |
| `SCAN_ZONE_RESOLVER` | string | empty |  |  | DNS resolver scan-zone routing resolves host names with: `system` (the platform's own resolver, which may know internal names) or `host[:port]` of a recursive resolver. Unset: a public resolver when organizations are self-service, otherwise `system`. |
| `SENSOR_MTLS_CA_CERT_FILE` | path | empty |  |  | Sensor CA certificate (PEM) for protocol v3 client certificates. Set together with `SENSOR_MTLS_CA_KEY_FILE`; unset, the CA is created once in `SENSOR_MTLS_CA_DIR`. |
| `SENSOR_MTLS_CA_DIR` | path | `data/sensor-ca` |  |  | Where the sensor CA is created on first start when the two CA files are not set. Keep it on a persistent volume. |
| `SENSOR_MTLS_CA_KEY_FILE` | path | empty |  |  | Sensor CA private key (PEM). Not the job signer's key. |
| `SENSOR_MTLS_CERT_TTL` | duration | `168h` |  |  | Lifetime of sensor client certificates, clamped to 1h..720h. |
| `SENSOR_MTLS_LISTEN_ADDR` | string | `:8443` |  |  | TLS 1.3 listener of sensor protocol v3 (gRPC). The gateway passes connections that offer the sensor ALPN id through to it. |
| `SENSOR_MTLS_TRUSTED_PROXIES` | list | empty |  |  | Comma-separated CIDRs whose PROXY protocol v2 header the sensor listener believes: the gateway that passes sensor connections through. |
| `SENSOR_PUBLIC_HOST` | string | empty |  |  | `host[:port]` sensors dial for protocol v3, for a dedicated sensor host name or port. Unset: the host and port of `SENSOR_PUBLIC_API_URL`, else `APP_URL`. Advertised only while the self-probe passes. |
| `SENSOR_RESULT_QUARANTINE_PURGE_INTERVAL` | duration | `24h` |  |  | How often reviewed quarantined sensor results older than the retention are deleted. Pending items are never purged. |
| `SENSOR_RESULT_QUARANTINE_RETENTION` | duration | `720h` |  |  | How long a reviewed quarantined sensor result is kept. |
| `SENSOR_TRANSPORT_V3` | auto \| off | `auto` |  |  | `auto` serves sensor protocol v3 and picks its bindings itself (HTTPS always, gRPC once the sensor CA loads and its self-probe passes). `off` is the emergency switch: every sensor falls back to v2 at its next call. |
| `SIGNER_SOCKET` | path | empty |  |  | Unix socket of the job signer (`cmd/signer`). Set: every job handed to a sensor is signed, and a job the signer refuses is not handed out. Unset: jobs are not signed. |
| `SIGNER_TIMEOUT` | duration | `2s` |  |  | Timeout of one call to the job signer. |

### Ingest

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `INGEST_COVERAGE_AUTO_RESOLVE` | string | `dry_run` |  |  | Coverage-scoped auto-resolve of non-repository findings: `off`, `dry_run` (log, metric and audit entry only) or `enforce`. |
| `INGEST_MAX_PENDING_PER_TENANT` | int | `100` |  |  | Queue depth per organization in `async` mode; further submissions get `429` with `Retry-After`. `0` turns the check off. |
| `INGEST_MODE` | string | `sync` |  |  | `sync`: scan results are processed in the request. `async`: results are stored, answered with `202` and processed by the ingest worker. |
| `INGEST_SOURCE_RESOLVE` | string | `dry_run` |  |  | Resolve a finding when a connector source reports it mitigated: `off`, `dry_run` or `enforce`. |
| `INGEST_VEX` | string | `dry_run` |  |  | How a VEX `not_affected` statement in a scan report acts on the matching open finding: `off`, `dry_run` or `enforce`. A false positive needs four-eyes, so `enforce` requests one (a pending approval by the actor `vex`, with the justification) that a person with `findings:approve` decides; it never sets the status itself. |
| `SENSOR_PROTOCOL_V2_RESULTS` | bool | `true` |  |  | Serve sensor protocol v2 results at `/api/v2/sensor`. Sensors need it; keep it on. |
| `SENSOR_V2_BLINDING_MIN_FINDINGS` | int | `100` |  |  | The guard applies only when more than this many findings would close. |
| `SENSOR_V2_BLINDING_RATIO` | float | `0.5` |  |  | Blinding guard: an auto-resolve that would close more than this fraction of a tool's open findings on the report's assets is held for review. |

### Discovery feeds and background jobs

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `CERT_MONITOR_CERTSPOTTER_URL` | string | `https://api.certspotter.com` |  |  | Fallback CT search service when the primary fails. `off` disables the fallback. |
| `VERSION_CHECK_ENABLED` | bool | `true` |  |  | Daily version check: one anonymous download of the signed release feed (no instance id, version or counts), compared with the running version on the instance; the platform console shows newer and security releases. `false` stops the download; offline import in the console still works. See `docs/architecture/version-check.md`. |
| `VERSION_CHECK_URL` | url | `https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json` |  |  | Where the version check reads the signed release feed (https only). Point it at an internal mirror if needed; the signature, not the host, is trusted. A mirror on a private address also needs the private egress allowlist. |
| `CERT_MONITOR_ENABLED` | bool | `true` |  |  | Certificate Transparency discovery sweep (passive, public data). `false` stops all outbound CT-log queries. |
| `CERT_MONITOR_FEED_URL` | string | `https://crt.sh` |  |  | CT-log search service queried per organization domain. |
| `CERT_MONITOR_INTERVAL` | duration | `24h` |  |  | How often the CT sweep runs. |
| `CERT_MONITOR_MAX_DOMAINS_PER_RUN` | int | `50` |  |  | Domains of one organization queried per sweep; the rest rotate in on later runs. |
| `CTEM_ID_FEED_URL` | string | `https://ctem.org/source.json` |  |  | CTEM-ID catalog feed mirrored daily. |
| `EASM_DNS_CHECK_INTERVAL` | duration | `24h` |  |  | How often the DNS checks run. |
| `EASM_DNS_CHECKS_ENABLED` | bool | `true` |  |  | Daily DNS-only checks of each organization's own names (dangling CNAME/NS, email posture). `false` turns them off platform-wide. |
| `EASM_DNS_MAX_NAMES_PER_RUN` | int | `500` |  |  | Names checked per organization per run. |
| `EASM_DNS_QPS` | float | `20` |  |  | DNS queries per second across all organizations. |
| `EASM_DNS_RESOLVER` | string | empty |  |  | Recursive resolver (`host[:port]`) the DNS checks use. Unset: the first nameserver in `/etc/resolv.conf`. |
| `SCM_SYNC_INTERVAL` | duration | `0` |  |  | Interval of the scheduled repository and branch sync of SCM integrations (for example `6h`). Off: repositories are imported on demand only. |
| `ASSET_ENRICHMENT_DAILY_BUDGET` | int | `2000` |  |  | Most assets one organization sends to automatic enrichment per 24 hours. |
| `ASSET_ENRICHMENT_ENABLED` | bool | `true` |  |  | Automatic passive enrichment of new assets, platform-wide. Each organization can still turn it off. |
| `ASSET_COVERAGE_ENABLED` | bool | `true` |  |  | The asset coverage loop, platform-wide: every asset gets the capabilities its type needs (RFC-093). |
| `ASSET_COVERAGE_DAILY_BUDGET` | int | `5000` |  |  | Most asset and capability pairs one organization's automatic coverage attempts per 24 hours. |
| `ASSET_COVERAGE_INTERVAL` | duration | `1m` |  |  | How often the asset coverage loop runs. |
| `FEED_CACHE_DIR` | path | `<system temp dir>/openctem-feeds` |  |  | Directory holding verified feed chunks between imports. |
| `PROGRAMFEED_DIR` | path | empty |  |  | Directory holding the newest signed public program feed bundle (a mirror or an upload). Needs `PROGRAMFEED_ROOT_KEY_ID`. |
| `PROGRAMFEED_LOCAL_BUNDLE_DIR` | path | empty |  |  | Directory of the operator's own unsigned local-only program bundle (`programfeed build --local-only`). Read only while a platform administrator has that source enabled. |
| `PROGRAMFEED_MIRRORS` | list | empty |  |  | Comma-separated https mirrors of the chunked program feed, tried after `PROGRAMFEED_URL`. |
| `PROGRAMFEED_ROOT_KEY_ID` | string | empty |  |  | Pinned offline root key id of the public program feed. Unset: no program feed is imported. |
| `PROGRAMFEED_URL` | url | empty |  |  | https release URL of the chunked public program feed, tried before `PROGRAMFEED_DIR`. |
| `VULNFEED_BASE_URL` | url | `https://github.com/openctemio/vulnfeed/releases` |  |  | Release base URL of the signed vulnerability bundles. |
| `VULNFEED_BUNDLE_DIR` | path | empty |  |  | Air-gapped platforms: local directory holding a vulnerability bundle release's files. |
| `VULNFEED_MIRRORS` | list | empty |  |  | Comma-separated https mirrors tried after the release for chunked vulnerability bundles. |
| `VULNFEED_ROOT_KEY_ID` | string | empty |  |  | Pinned root key id of the vulnerability bundles. Unset: no bundle is imported. |

### Integrations

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `GITHUB_APP_ID` | int | empty |  |  | The GitHub App's numeric id (RFC-077). With the slug, client id and secret, private key and webhook secret it turns on the gate check and pull request comments; a partial configuration leaves the app off and is logged. |
| `GITHUB_APP_SLUG` | string | empty |  |  | The GitHub App's URL name, used for its install link. |
| `GITHUB_APP_CLIENT_ID` | string | empty |  |  | The GitHub App's OAuth client id (binding an installation to an organization). |
| `GITHUB_APP_CLIENT_SECRET` | string | empty |  | yes | The GitHub App's OAuth client secret. |
| `GITHUB_APP_PRIVATE_KEY_FILE` | path | empty |  |  | File holding the GitHub App's private key (PEM). Preferred over `GITHUB_APP_PRIVATE_KEY`. |
| `GITHUB_APP_PRIVATE_KEY` | string | empty |  | yes | The GitHub App's private key (PEM) itself, when a file cannot be mounted. |
| `GITHUB_APP_WEBHOOK_SECRET` | string | empty |  | yes | HMAC secret of the GitHub App's webhook deliveries. |
| `GITHUB_APP_API_URL` | url | empty |  |  | GitHub API base URL for GitHub Enterprise Server. Unset: api.github.com. |
| `GITHUB_APP_WEB_URL` | url | empty |  |  | GitHub web base URL for GitHub Enterprise Server. Unset: github.com. |
| `OPENCTEM_HTTPSEC_ALLOW_PRIVATE` | string | `unset` |  |  | `1` opens every private range. Honored only with `APP_ENV=development`: with any other `APP_ENV` (or none) the API refuses to start, because it would open the platform's own network to every organization. Use `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` instead. Any value other than empty, `0` or `1` is refused. |
| `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` | string | empty |  |  | Comma-separated private ranges that outbound calls of the API (webhook and notification channels, self-hosted Jira or GitLab, an SMTP relay) may reach, for example `10.20.0.0/16`. Each entry must be a CIDR inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fc00::/7`, otherwise the API refuses to start. The list applies to every organization, so name only the subnets of your own services. Loopback, link-local, CGNAT and cloud metadata addresses stay blocked whatever the list says. |

### Metrics

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `METRICS_PUBLIC` | bool | `false` |  |  | `true` serves `/metrics` without a token. Use it only when the port is reachable from a private scrape network alone. |
| `METRICS_TOKEN` | string | empty |  | yes | Bearer token required on `GET /metrics` (`Authorization: Bearer <token>` or `X-Metrics-Token`). Empty and `METRICS_PUBLIC=false`: `/metrics` answers 404. |

### Audit log retention

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `ADMIN_AUDIT_RETENTION_BATCH_SIZE` | int | `10000` |  |  | Rows per delete transaction. |

### Admin console

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `ADMIN_ALLOWED_CIDRS` | list | `127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7` |  |  | Comma-separated CIDRs or addresses of the client networks that may reach the platform admin console (`/api/v1/admin`); others get 403 `ADMIN_NETWORK_NOT_ALLOWED`. Default: private networks only. Set `0.0.0.0/0,::/0` for an internet-facing console. The client address is the TCP peer unless it is in `SERVER_TRUSTED_PROXIES` (then `X-Forwarded-For`): behind the web console and the gateway, list them there, or every console request looks like it comes from their private address. |
| `ADMIN_LISTEN_ADDR` | string | empty |  |  | The platform admin console's own listener, a loopback or private IP and port, e.g. `10.0.0.5:8081` (any other address needs `ADMIN_LISTEN_ALLOW_ALL_INTERFACES=true`). Set: `/api/v1/admin` is served only there (plain HTTP, internal: the gateway's admin site and the web console reach it) and the main listener answers 404 for it; the admin listener answers 404 for everything else but `/health`. Empty: the console shares the main listener. |
| `ADMIN_LISTEN_ALLOW_ALL_INTERFACES` | bool | `false` |  |  | `true` lets `ADMIN_LISTEN_ADDR` be any address: every interface (`:8081`, `0.0.0.0:8081`), a public or link-local IP, or a hostname. Off: only a loopback or private IP (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) is accepted and the API refuses to start otherwise. Set it only when the network itself keeps the port private, such as a container network with no published port. |
| `ADMIN_ELEVATION` | string | `required` |  |  | `required`: platform administrators act as read-only until they elevate their console session to a role no higher than their own, for 15 to 60 minutes, with a reason and a fresh confirmation (audited). `off`: they act as their own role from sign-in. |

### Audit log retention

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `ADMIN_AUDIT_SINK` | string | empty |  |  | Streams the platform administrators' audit log off the box: every row with its hash-chain position and hash (no request body), and the chain head every `ADMIN_AUDIT_SINK_HEAD_INTERVAL`. `https://collector/path` (one JSON object per POST, `Authorization: Bearer ADMIN_AUDIT_SINK_TOKEN`, no redirects), `syslog+tls://host:6514`, `syslog+tcp://host:514`, `syslog+udp://host:514` (RFC 5424) or `file:///path` (JSON lines, 0600). A destination that cannot be used stops the start-up. Empty: off. |
| `ADMIN_AUDIT_SINK_TOKEN` | string | empty |  | yes | Bearer token sent to an `https://` `ADMIN_AUDIT_SINK`. |
| `ADMIN_AUDIT_SINK_HEAD_INTERVAL` | duration | `15m` |  |  | How often the administrators' audit chain head (position and hash) is sent to `ADMIN_AUDIT_SINK`. A later re-signing of the chain cannot match a head already sent. |
| `ADMIN_AUDIT_RETENTION_DAYS` | int | `365` |  |  | Age threshold. At least 30 when deletion is enabled. |
| `ADMIN_AUDIT_RETENTION_DRY_RUN` | bool | `true` |  |  | Report what would be deleted instead of deleting. Set `false` to enforce retention (irreversible). |
| `ADMIN_AUDIT_RETENTION_ENABLED` | bool | `true` |  |  | Run the platform admin audit-log retention controller. |
| `ADMIN_AUDIT_RETENTION_INTERVAL` | duration | `24h` |  |  | How often the controller runs. |
| `AUDIT_ARCHIVE_DIR` | string | empty |  |  | Directory for the gzip JSONL archives. Empty: nothing is deleted. Back it up like the database. |
| `AUDIT_RETENTION_DAYS` | int | `365` |  |  | Organization audit entries older than this are archived and deleted, keeping the hash chain verifiable. |
| `ADMIN_SESSION_PURGE_INTERVAL` | duration | `1h` |  |  | How often platform-admin console sessions past their absolute expiry are deleted. |
| `ASSET_CHANGE_RETENTION_DAYS` | int | `400` |  |  | Days the asset change timeline keeps events. Minimum 30. |
| `INVITATION_PURGE_INTERVAL` | duration | `1h` |  |  | How often expired, unaccepted invitations are deleted. |

### AI triage

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `AI_AUTO_TRIAGE_DEFAULT_ENABLED` | bool | `false` |  |  | Platform default for automatic triage of new findings; an organization's own setting wins. |
| `AI_AUTO_TRIAGE_DEFAULT_SEVERITIES` | list | `critical,high` |  |  | Platform default severities for automatic triage. |
| `AI_AUTO_TRIAGE_DELAY` | duration | `60s` |  |  | Delay before an automatic triage job runs. |
| `AI_MAX_TOKENS` | int | `4096` |  |  | Maximum tokens per request. |
| `AI_PLATFORM_MODEL` | string | `claude-sonnet-4-20250514` |  |  | Model name passed to the provider. |
| `AI_PLATFORM_PROVIDER` | string | `claude` |  |  | Provider used for organizations in platform mode: `claude`, `openai` or `gemini`. |
| `AI_RATE_LIMIT_RPM` | int | `60` |  |  | Completions per minute per API key. `0` or less turns the cap off. |
| `AI_TEMPERATURE` | float | `0.1` |  |  | Sampling temperature (0.0 to 1.0). |
| `AI_TIMEOUT_SECONDS` | int | `30` |  |  | Timeout of one provider call. |
| `AI_TRIAGE_BUDGET_DEFAULT_TOKENS` | int | `0` |  |  | Monthly token budget of an organization without its own. |
| `AI_TRIAGE_BUDGET_ENABLED` | bool | `false` |  |  | Enforce the per-organization monthly token budget. |
| `AI_TRIAGE_BUDGET_STRICT` | bool | `false` |  |  | With the budget on: refuse triage when the budget store cannot be read (otherwise log and continue). |
| `AI_TRIAGE_ENABLED` | bool | `false` |  |  | Deprecated and ignored: availability follows the provider keys and the AI triage module. |
| `AI_TRIAGE_RECOVERY_BATCH_SIZE` | int | `50` |  |  | Jobs recovered per run. |
| `AI_TRIAGE_RECOVERY_ENABLED` | bool | `true` |  |  | Requeue triage jobs stuck in processing. |
| `AI_TRIAGE_RECOVERY_INTERVAL` | duration | `5m` |  |  | How often stuck jobs are looked for. |
| `AI_TRIAGE_RECOVERY_STUCK_DURATION` | duration | `15m` |  |  | Age after which a processing job counts as stuck. |
| `ANTHROPIC_API_KEY` | string | empty |  | yes | Platform key for the `claude` provider. AI triage is available when at least one provider key is set and the AI triage module is enabled for the organization. |
| `GEMINI_API_KEY` | string | empty |  | yes | Platform key for the `gemini` provider. |
| `OPENAI_API_KEY` | string | empty |  | yes | Platform key for the `openai` provider. |

## Administration tools

Read by the command-line tools shipped with the server (`bootstrap-admin`, `rekey`, `openctem-signer`, ...), in addition to the database variables.

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `BOOTSTRAP_SMTP_HOST` | string | empty |  |  | `bootstrap-admin`: SMTP server stored as the platform e-mail setting when none is stored (headless installs). Change it later in the admin console (System > E-mail). |
| `BOOTSTRAP_SMTP_PORT` | string | empty |  |  | `bootstrap-admin`: SMTP port (default 587). |
| `BOOTSTRAP_SMTP_USER` | string | empty |  |  | `bootstrap-admin`: SMTP user name. |
| `BOOTSTRAP_SMTP_PASSWORD` | string | empty |  | yes | `bootstrap-admin`: SMTP password, stored encrypted with `APP_ENCRYPTION_KEY`. |
| `BOOTSTRAP_SMTP_FROM` | string | empty |  |  | `bootstrap-admin`: sender address. |
| `BOOTSTRAP_SMTP_FROM_NAME` | string | empty |  |  | `bootstrap-admin`: sender name (default `BRAND_NAME`, else OpenCTEM). |
| `BOOTSTRAP_SMTP_STARTTLS` | string | empty |  |  | `bootstrap-admin`: `false` turns STARTTLS off (default on). |
| `ADMIN_BACKUP_EMAIL` | string | empty |  |  | `bootstrap-admin`: e-mail of the break-glass backup administrator. |
| `ADMIN_BACKUP_NAME` | string | empty |  |  | `bootstrap-admin`: display name of the backup administrator. |
| `ADMIN_EMAIL` | string | empty |  |  | `bootstrap-admin`: e-mail of the first platform administrator (or `-email`). |
| `ADMIN_NAME` | string | empty |  |  | `bootstrap-admin`: display name of the first platform administrator. |
| `DATABASE_URL` | string | built from `DB_*` |  |  | Connection URL the start-up migrations use when `DATABASE_MIGRATE_URL` and `DB_MIGRATE_USER` are unset. A password in it must be percent-encoded (`@` is `%40`, `:` is `%3A`, `/` is `%2F`, `%` is `%25`); the URL built from `DB_*` is encoded for you. |
| `ORG_NAME` | string | empty |  |  | `bootstrap-admin`: create the first organization with this name (needs `ORG_OWNER_EMAIL`). |
| `ORG_OWNER_EMAIL` | string | empty |  |  | `bootstrap-admin`: owner of the first organization; a new account gets a one-time set-password link. |
| `ORG_OWNER_NAME` | string | empty |  |  | `bootstrap-admin`: display name of a new owner account. |
| `ORG_SLUG` | string | empty |  |  | `bootstrap-admin`: URL slug of the first organization. Unset: derived from `ORG_NAME`. |
| `REKEY_NEW_KEY` | string | empty |  | yes | `rekey`: the new encryption key. |
| `REKEY_NEW_KEY_FORMAT` | string | empty |  |  | `rekey`: format of `REKEY_NEW_KEY`. Unset: detected. |
| `REKEY_OLD_KEY` | string | empty |  | yes | `rekey`: the encryption key being retired. |
| `REKEY_OLD_KEY_FORMAT` | string | empty |  |  | `rekey`: format of `REKEY_OLD_KEY` (`hex`, `base64` or `raw`). Unset: detected. |
| `SIGNER_KEYSET_FILE` | string | empty |  |  | `openctem-signer`: the root-signed keyset the signer serves to sensors. |
| `SIGNER_KEY_FILE` | string | empty |  |  | `openctem-signer`: the job-signing private key (PEM, mode 0400). |
| `SIGNER_LEDGER` | string | empty |  |  | `openctem-signer`: scope ledger mode (`enforce`, `audit` or `off`). |
| `SIGNER_LEDGER_MIN_APPROVALS` | string | empty |  |  | `openctem-signer`: approvals the ledger requires for a scope change. |
| `SIGNER_LEDGER_T2_MIN_APPROVALS` | string | empty |  |  | `openctem-signer`: approvals the ledger requires for a tier-2 scope change. |
| `SIGNER_SENSOR_BURST` | string | empty |  |  | `openctem-signer`: burst of `SIGNER_SENSOR_RATE`. |
| `SIGNER_SENSOR_RATE` | string | empty |  |  | `openctem-signer`: signatures per second allowed per sensor. |
| `SIGNER_STATE_DIR` | string | empty |  |  | `openctem-signer`: directory of the signing log and scope ledger. Keep it on a persistent volume. |
| `SIGNER_TENANT_BURST` | string | empty |  |  | `openctem-signer`: burst of `SIGNER_TENANT_RATE`. |
| `SIGNER_TENANT_RATE` | string | empty |  |  | `openctem-signer`: signatures per second allowed per organization. |

## Web console

Read by the Next.js web console. `NEXT_PUBLIC_*` values are compiled into the browser bundle at build time: never put a secret in one.

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `ADMIN_API_URL` | string | empty |  |  | Internal URL of the API's console listener (`ADMIN_LISTEN_ADDR`), where the console's proxy sends `/api/v1/admin`. Unset: `BACKEND_API_URL`. Compose: `http://api:8081`. |
| `OPENCTEM_ADMIN_PLANE` | string | `shared` |  |  | `separate`: the platform console has its own origin. Requests the gateway's console site marks `X-OpenCTEM-Plane: admin` reach only the console (anything else 404, `/` goes to `/admin`), and the main site answers 404 for the console. `shared`: one origin for both. Compose: `separate`. |
| `BACKEND_API_URL` | string | `http://localhost:8080` | yes |  | Internal URL of the API. The console proxies the browser's `/api/v1` calls and the WebSocket upgrade to it. Compose: `http://api:8080`. |
| `SECURE_COOKIES` | string | `true` |  |  | `Secure` flag on the cookies the console sets. Only `false` turns it off (local `http://` development). |
| `TRUST_PROXY_HEADERS` | string | `false` |  |  | Forward `X-Real-IP` / `X-Forwarded-For` to the API. Set `true` only when a proxy in front of the console overwrites those headers (the gateway does), otherwise a browser could choose its own address. |
| `COOKIE_MAX_AGE` | string | `604800` |  |  | Lifetime in seconds of the session cookies the console sets. |
| `NODE_ENV` | string | `production` |  |  | Node.js environment. |
| `PORT` | string | `3000` |  |  | Listen port and address of the console. |
| `HOSTNAME` | string | `0.0.0.0` |  |  | Listen address of the console. |
| `NEXT_PUBLIC_APP_URL` | string | `http://localhost:3000` |  |  | Public origin of the console, used for the Content-Security-Policy and auth redirects. Set to the platform's public URL. |
| `NEXT_PUBLIC_WS_BASE_URL` | string | empty |  |  | WebSocket base URL. Unset: the console's own origin. |
| `NEXT_PUBLIC_SENTRY_DSN` | string | empty |  |  | Sentry DSN for browser and server error reporting. Unset: off. |
| `NEXT_PUBLIC_APP_DESCRIPTION` | string | empty |  |  | Page description meta tag. |
| `NEXT_PUBLIC_COOKIE_DOMAIN` | string | empty |  |  | Cookie domain for the console's cookies. Unset: the host only. |
| `NEXT_PUBLIC_ENABLE_SIDEBAR_BADGES` | string | `false` |  |  | Show live count badges in the sidebar. |
| `NEXT_ALLOWED_DEV_ORIGINS` | string | empty |  |  | Development server only: extra origins allowed to load the dev bundle. |

## Gateway

Read by the bundled Caddy gateway (`api/deploy/gateway`).

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `OPENCTEM_TLS_MODE` | string | none in the entrypoint (`internal` in Compose and the all-in-one image) | yes |  | `internal`, `acme`, `files` or `http`. |
| `ACME_EMAIL` | string | empty |  |  | Let's Encrypt account contact. |
| `ACME_CA` | string | `Let's Encrypt production directory` |  |  | ACME directory URL, for example a staging or private ACME CA. |
| `TLS_CERT_FILE` | string | `tls.crt` |  |  | File name of the certificate (full chain, PEM) inside `OPENCTEM_CERT_DIR`. |
| `TLS_KEY_FILE` | string | `tls.key` |  |  | File name of the key (PEM) inside `OPENCTEM_CERT_DIR`. |
| `OPENCTEM_CERT_DIR` | string | `/certs` |  |  | Directory holding the certificate in mode `files`. |
| `OPENCTEM_ALLOW_PLAIN_HTTP` | string | `false` |  |  | Must be `true` for mode `http`, which serves plain HTTP behind your own TLS proxy. |
| `OPENCTEM_TRUSTED_PROXIES` | string | `127.0.0.1/32` |  |  | Space-separated CIDRs of proxies in front of the gateway whose `X-Forwarded-For` it believes. |
| `OPENCTEM_CLIENT_IP_HEADERS` | string | `X-Forwarded-For` |  |  | Header(s) a proxy in `OPENCTEM_TRUSTED_PROXIES` carries the client address in, tried in order: `X-Forwarded-For` (read right to left), `Cf-Connecting-Ip` (Cloudflare Tunnel) or `True-Client-Ip`. Ignored from any other peer; the gateway then sends the API only the resolved address. |
| `GATEWAY_MAX_BODY_SIZE` | string | `256MB` |  |  | Largest request body the gateway accepts. The API enforces the per-route limits. |
| `AUTH_COOKIE_NAME` | string | `auth_token` |  |  | Session cookie name used by the routing rule that sends token clients to the API. |
| `OPENCTEM_GATEWAY_DIR` | string | `/etc/caddy` |  |  | Directory with `Caddyfile`, `planes.caddy` and `modes/`. |
| `XDG_DATA_HOME` | string | `/data` |  |  | Caddy storage: certificates, ACME account, internal CA. Keep it on a volume. |
| `OPENCTEM_API_UPSTREAM` | string | `api:8080` |  |  | Address of the API. |
| `OPENCTEM_WEB_UPSTREAM` | string | `web:3000` |  |  | Address of the web console. |
| `OPENCTEM_SENSOR_GATEWAY` | off \| alpn \| passthrough | `off` |  |  | Sensor protocol v3 routing: `alpn` passes connections that offer the sensor ALPN id to the API's sensor listener; `passthrough` also routes a dedicated sensor host name (`SENSOR_PUBLIC_HOSTNAME`). Needs a TLS mode and the gateway image with the layer4 module. |
| `SENSOR_PUBLIC_HOSTNAME` | string | empty |  |  | Dedicated DNS name sensors dial for protocol v3 (no port), with `OPENCTEM_SENSOR_GATEWAY=passthrough`. |
| `SENSOR_MTLS_UPSTREAM` | string | `api:8443` |  |  | Address of the API's sensor listener the gateway passes sensor connections to. |

## Docker Compose stack

Read by `api/deploy/docker-compose.yml` from its `.env` file.

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `OPENCTEM_HOSTNAME` | string | `none` | yes |  | DNS name or IP address browsers and sensors use; the gateway certificate is issued for it. |
| `OPENCTEM_CA_EXPORT_DIR` | string | `./ca` |  |  | Host directory the internal root CA is exported to. |
| `OPENCTEM_VERSION` | string | `none` | yes |  | Release tag of the API, web and migrations images, for example `v0.9.0`. |
| `OPENCTEM_PUBLIC_URL` | string | `https://<OPENCTEM_HOSTNAME>` | yes |  | Exact origin browsers use, when it is not `https://<OPENCTEM_HOSTNAME>` (a port other than 443). Passed to the API as `APP_URL`. |
| `API_IMAGE` | string | `ghcr.io/openctemio/openctem-api` |  |  | Image repository of the API. |
| `UI_IMAGE` | string | `ghcr.io/openctemio/openctem-web` |  |  | Image repository of the web console. |
| `MIGRATIONS_IMAGE` | string | `ghcr.io/openctemio/migrations` |  |  | Image repository of the migrations job. |
| `API_VERSION` | string | `OPENCTEM_VERSION` |  |  | Per-image tag override. Leave unset. |
| `UI_VERSION` | string | `OPENCTEM_VERSION` |  |  | Per-image tag override. Leave unset. |
| `GATEWAY_BIND` | string | `0.0.0.0` |  |  | Host interface the gateway port is published on. |
| `GATEWAY_HTTPS_PORT` | string | `443` |  |  | Published HTTPS port. |
| `GATEWAY_HTTP_PORT` | string | `80` |  |  | Port published by the overlays. |
| `TLS_CERT_DIR` | string | `./certs` |  |  | Host directory mounted at `/certs` (mode `files`). |
| `OPENCTEM_NET_PREFIX` | string | `172.30.80` |  |  | First three octets of the internal `/24`. The gateway is `.10`, the web console `.11`. |
| `CADDY_VERSION` | string | `2.11.4-alpine` |  |  | Image tag of the bundled gateway. |
| `POSTGRES_VERSION` | string | `17` |  |  | Image tag of the bundled PostgreSQL. |
| `REDIS_VERSION` | string | `7-alpine` |  |  | Image tag of the bundled Redis. |
| `DB_SUPERUSER` | string | `DB_USER` |  |  | PostgreSQL superuser, used only by `initdb` and the `db-roles` job. |
| `DB_SUPERUSER_PASSWORD` | string | `DB_PASSWORD` |  | yes | Password of `DB_SUPERUSER`. |
| `DB_MIGRATE_USER` | string | `unset` |  |  | Schema-owner role the migrations run as. Set to turn on the least-privilege layout. |
| `DB_MIGRATE_PASSWORD` | string | `unset` |  | yes | Password of `DB_MIGRATE_USER`. |
| `API_MEMORY_LIMIT` | string | `2g` |  |  | Memory limit of the `api` container. |
| `WEB_MEMORY_LIMIT` | string | `1g` |  |  | Memory limit of the `web` container. |
| `GATEWAY_MEMORY_LIMIT` | string | `512m` |  |  | Memory limit of the `gateway` container. |
| `API_GOMEMLIMIT` | string | `1600MiB` |  |  | `GOMEMLIMIT` of the `api` container: the Go runtime collects garbage to stay below it. Keep it about 80% of `API_MEMORY_LIMIT`. |
| `POSTGRES_MEMORY_LIMIT` | string | `4g` |  |  | Memory limit of the bundled `postgres` container; keep it above `shared_buffers` plus connections times `work_mem`. |
| `REDIS_MEMORY_LIMIT` | string | `1g` |  |  | Memory limit of the bundled `redis` container. |
| `SIGNER_MEMORY_LIMIT` | string | `256m` |  |  | Memory limit of the `signer` container (`docker-compose.job-signer.yml`). |

## All-in-one image

Read by the all-in-one image's supervisor.

| Variable | Type | Default | Required | Secret | Description |
|---|---|---|---|---|---|
| `GATEWAY` | string | `on` |  |  | `on`: only the gateway listens on a routable address (port 443); the API and console bind to `127.0.0.1`. `off`: the API listens on 8080 and the console on 3000, without the gateway. |
| `MIGRATE_ON_START` | string | `true` |  |  | Apply database migrations before starting, under a PostgreSQL advisory lock so several replicas do not migrate at once. |
| `DATABASE_MIGRATE_URL` | string | built from `DB_MIGRATE_USER` / `DB_MIGRATE_PASSWORD` |  |  | Connection URL of the schema owner for the start-up migrations. A password in it must be percent-encoded; the URL built from `DB_MIGRATE_USER` / `DB_MIGRATE_PASSWORD` is encoded for you. |
| `WEB_HOSTNAME` | string | `127.0.0.1` |  |  | Listen address of the web console. |

## Retired and removed names

The API refuses to start while one of these is set, and says what to do instead.

| Variable | Instead |
|---|---|
| `AGENT_CONFIG_TEMPLATES_DIR` | rename it to `SENSOR_CONFIG_TEMPLATES_DIR` |
| `AGENT_PUBLIC_API_URL` | rename it to `SENSOR_PUBLIC_API_URL` |
| `AGENT_KEY_TTL` | rename it to `SENSOR_KEY_TTL` |
| `AGENT_LB_JOB_WEIGHT` | rename it to `SENSOR_LB_JOB_WEIGHT` |
| `AGENT_LB_CPU_WEIGHT` | rename it to `SENSOR_LB_CPU_WEIGHT` |
| `AGENT_LB_MEMORY_WEIGHT` | rename it to `SENSOR_LB_MEMORY_WEIGHT` |
| `AGENT_LB_DISK_IO_WEIGHT` | rename it to `SENSOR_LB_DISK_IO_WEIGHT` |
| `AGENT_LB_NETWORK_WEIGHT` | rename it to `SENSOR_LB_NETWORK_WEIGHT` |
| `AGENT_LB_MAX_DISK_THROUGHPUT_MBPS` | rename it to `SENSOR_LB_MAX_DISK_THROUGHPUT_MBPS` |
| `AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS` | rename it to `SENSOR_LB_MAX_NETWORK_THROUGHPUT_MBPS` |
| `SENSOR_TRANSPORT_V3_ENABLED` | rename it to `SENSOR_TRANSPORT_V3=auto\|off` |
| `SCOPE_ACTIVE_PROOF` | remove it; a platform administrator sets "Require a verified domain before platform sensors scan a target" in Console > System > Platform scanning |
| `APP_DEBUG` | unset it; it switched nothing on (use LOG_LEVEL=debug outside production) |
| `GRPC_PORT` | unset it; nothing listened on it, sensors reach protocol v3 on SENSOR_MTLS_LISTEN_ADDR |
| `LOG_SKIP_HEALTH` | unset it; health, readiness and metrics requests are never written to the request log |
| `AI_MAX_CONCURRENT_JOBS` | unset it; it limited nothing, AI triage jobs run on the background job queue |
| `AUTH_ALLOW_REGISTRATION` | unset it; who may sign up is the sign-up policy (Console > System > Sign-up) |
| `TENANT_CREATION_MODE` | unset it and set SIGNUP_MODE: admin_only is SIGNUP_MODE=disabled (the default), self_service is SIGNUP_MODE=open |
| `SMTP_ENABLED` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_HOST` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_PORT` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_USER` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_PASSWORD` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_FROM` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_FROM_NAME` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_TLS` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_SKIP_VERIFY` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `SMTP_TIMEOUT` | unset it; the platform SMTP server is set in the admin console (System > E-mail); headless installs pass BOOTSTRAP_SMTP_* to bootstrap-admin |
| `APP_ALLOW_PLAINTEXT_CREDENTIALS` | unset it; credentials are always encrypted (development uses the key in api/.env.example) |
| `CTEM_ENFORCE_COVERAGE_SLO` | unset it; owners and admins set it per organization on the Cycles page (PUT /api/v1/organization/settings/cycles) |
| `AUTH_ACCESS_TOKEN_COOKIE_NAME` | unset it; the session cookie is always auth_token |
| `AUTH_REFRESH_TOKEN_COOKIE_NAME` | unset it; the refresh cookie is always refresh_token |
| `AUTH_TENANT_COOKIE_NAME` | unset it; the organization cookie is always app_tenant |
| `JIRA_WEBHOOK_SECRET` | unset it; each Jira integration has its own webhook secret (Settings > Integrations > Ticketing, or POST /api/v1/integrations/{id}/jira-webhook/secret/rotate) |
| `SENSOR_LATEST_VERSION` | unset it; each sensor product's release line is built into the API from versions.yaml and changes with an API upgrade |
| `SENSOR_MIN_VERSION` | unset it; each sensor product's release line is built into the API from versions.yaml and changes with an API upgrade |
| `SENSOR_SDK_LATEST_VERSION` | unset it; each sensor product's release line is built into the API from versions.yaml and changes with an API upgrade |
| `SENSOR_SDK_MIN_VERSION` | unset it; the SDK release is informational, sensor compatibility is the protocol and capabilities; SDK releases with a security advisory are listed in versions.yaml sdk.advisories |
