# RFC-079: Run-time settings in the console instead of environment variables

| | |
|---|---|
| Status | Accepted, partly implemented (2026-10-18) |
| Scope | api (`internal/app/platformsettings`, admin console routes, the e-mail sender, the auth policy, the OAuth providers, the AI provider, discovery and retention jobs), web (admin console > System pages, en + vi), `internal/config` (variables removed and refused) |
| Related | RFC-022 (admin console), RFC-025 (sign-up policy, the first setting moved this way), RFC-074 (adaptive sensor control), the environment variable registry (`api/internal/config/env_registry.yaml`) |

## 1. Summary

About 100 of the API's 260 environment variables are decisions an
administrator makes while the platform runs: platform e-mail, the sign-in
policy, sign-in providers, the AI provider, discovery job budgets, data
retention, legal pages. Today each change needs host access, an edit of the
deployment file and a restart, and an install cannot send e-mail until someone
edits `SMTP_*` by hand. This RFC moves them to the admin console with one
mechanism, and removes the variables.

Variables that must stay in the environment are untouched: database and Redis
connections, the root encryption key and the session secret, listen addresses
and TLS files, trust boundaries (trusted proxies, sensor CA, job signer) and
trust anchors (feed root key ids). A console user must never be able to widen
what the platform trusts.

## 2. Design

### 2.1 One settings mechanism

- **Storage**: `platform_settings` (key, value JSON, version, source,
  updated_by, updated_at), the table the sign-up policy already uses. One key
  per group (`email.smtp`, `auth.policy`, `auth.providers`, `ai.provider`,
  `jobs.discovery`, `retention`, `legal`).
- **Definitions**: each group is a typed Go struct with defaults, bounds and
  a `secret` tag per field, so the API validates and the console renders
  from one definition.
- **Reads**: a cached getter that checks the row version, so a change applies
  without a restart.
- **Writes**: compare-and-swap on the version (a stale save is refused, not
  merged), then the admin audit log entry with old and new values for
  non-secret fields and "changed" for secret ones.
- **Authorization**: platform administrators only (the admin console's
  existing gate); no organization role can read or write platform settings.

### 2.2 Secrets entered in the console

- Encrypted at rest with AES-256-GCM under `APP_ENCRYPTION_KEY`, the code that
  protects integration credentials.
- Write-only: reads return `configured: true|false`, never the value; changing
  one needs re-entering it; clearing it is an explicit action.
- Never logged, never in the audit log, never in an error message.
- Covered by the encryption key rotation (`cmd/rekey`) like every other stored
  secret.

### 2.3 Floors stay in code

Production refuses weak values today (`AUTH_PASSWORD_MIN_LENGTH` < 8, email
verification off with local sign-in, ...). The same floors apply to console
values: the API refuses to save below them, and the console shows the floor.

### 2.4 No double source of truth

When a group moves, its variables are removed and refused at startup with a
hint (`removedEnv`), not kept as a fallback. A first-start seed from the
environment (the pattern `TENANT_CREATION_MODE` uses) is allowed only where an
install must work before anyone signs in; for e-mail, `bootstrap-admin` takes
the SMTP values instead (§4, Q1).

## 3. Groups and order

| Order | Group | Variables removed | Console page |
|---|---|---|---|
| 1 | Platform e-mail | `SMTP_*` (10) | System > E-mail, with "send test e-mail" |
| 2 | Legal pages and security.txt | `LEGAL_*` (11), `SECURITY_*` (3), `NEXT_PUBLIC_TERMS_URL`, `NEXT_PUBLIC_PRIVACY_URL` | System > Legal |
| 3 | Sign-in policy | `AUTH_PASSWORD_*`, `AUTH_MAX_LOGIN_ATTEMPTS`, `AUTH_LOCKOUT_DURATION`, `AUTH_MAX_ACTIVE_SESSIONS`, `AUTH_REQUIRE_EMAIL_VERIFICATION`, token and session durations, `SESSION_TIMEOUT_MINUTES` | Security > Sign-in policy |
| 4 | Sign-in providers | `OAUTH_*`, platform `SSO_ENTRA_*`, `CAPTCHA_TURNSTILE_*` | Security > Sign-in providers, System > Sign-up |
| 5 | AI provider | `AI_*`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` | System > AI |
| 6 | Discovery jobs | `CERT_MONITOR_*` intervals and budgets, `EASM_DNS_*`, `ASSET_ENRICHMENT_*` | Operations > Discovery |
| 7 | Retention | `AUDIT_RETENTION_DAYS`, `ASSET_CHANGE_RETENTION_DAYS`, `ADMIN_AUDIT_RETENTION_*` | System > Data retention |

E-mail first: sign-up, invitations, verification and password reset depend on
it, and production requires email verification while SMTP is optional.

Per organization, the same move already happened for the cycle close policy
(`CTEM_ENFORCE_COVERAGE_SLO` → organization settings).

## 4. Questions

- **Q1.** E-mail: console only (recommended; `bootstrap-admin` sets it for
  headless installs) or an env seed on the first start?
- **Q2.** Legal pages: the web console reads them per request from a public,
  unauthenticated, cached API endpoint (non-secret values only). Recommended.

## 5. Security

- Threat: a compromised platform administrator session. It can change what
  this RFC moves (e-mail relay, sign-in policy within the floors, providers)
  but none of the trust settings that stay in the environment, and every change
  is in the admin audit log. Step-up authentication is required for groups 1,
  3 and 4.
- Threat: secret disclosure through the API or logs. Write-only fields, no
  value in audit, logs or errors, encryption at rest.
- Tenant isolation: platform settings are not tenant data; organization
  settings keep their own store and routes.

## 6. Implementation

One PR for the mechanism (store, typed definitions, getter, audit, secret
handling, tests), then one PR per group (API + console page + variables
removed + docs regenerated), each with authorization and secret-handling tests
and en + vi text.

## 7. Revision 2026-10-18: lock and default instead of removal

Operating experience changed one rule of §2.4: a variable that an installer
kit or a secret file already sets keeps working. For each moved setting the
environment is one of:

- a **lock**: when set, it pins the setting and the console shows "locked by
  the server configuration (NAME)" (CAPTCHA keys, deployment region, platform
  AI keys);
- a **default**: used until the console stores a value (storage quota);
- a **ceiling**: the console may only tighten it (`SIGNUP_MODE`,
  `VERSION_CHECK_ENABLED=false`).

Shipped (one shared mechanism, `internal/app/consolesetting`: typed value,
15-second cache, compare-and-swap, audit with the reason and a notice to
every administrator):

| Setting | Key | Guard | Test button |
|---|---|---|---|
| CAPTCHA (Turnstile) | `captcha.turnstile` | super admin, fresh confirmation, reason, critical audit, notice | check the secret with Turnstile |
| Deployment region (once, before the first organization) | `deployment.region` | same; immutable once set | — |
| Default storage quota (+ limit key `storage_mb` per organization) | `storage.tenant_quota_mb` | super admin, step-up, audit | — |
| Alert webhook | `alerts.webhook` | guarded; SSRF-guarded HTTPS; address and secret write-only | send a test alert |
| Platform AI provider | `ai.platform` | guarded; off by default | one-token request |

Still planned from §3: sign-in policy (tighten-only), social sign-in
providers, discovery jobs, retention (shown read-only), sensor public URL,
log level. Design and order: the console configuration plan of the platform
console (`docs/architecture/platform-console.md`, "Settings moved from the
environment").
