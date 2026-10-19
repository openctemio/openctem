# Platform console: its own service, site and plane

Design: [RFC-022](../rfcs/RFC-022-platform-admin-console.md), revisions 20
and 21. This page is how the platform administration console is built and
deployed today.

## Components

| Part | Where | What it does |
|------|-------|--------------|
| Console app | `web/console/` (Next.js), image `ghcr.io/openctemio/openctem-console` | The console's pages at the root of its site (`/`, `/login`, `/organizations`, `/users`, `/requests`, `/support`, `/scanning/…`, `/security/…`, `/system/…` for the settings pages, `/health`), its API proxy `/api/v1/admin/*` and `/api/health`. Shares `web/`'s packages and imports shared code from `web/src`; contains no tenant route. |
| Tenant web app | `web/src/` (Next.js), image `openctem-web` | No console route, page or client; refuses to proxy `/api/v1/admin` however the path is spelled. |
| Gateway console site | `api/deploy/gateway/admin/on.site` | `https://<host>:<OPENCTEM_ADMIN_PORT>` (port mode, default 8443) or `https://<OPENCTEM_ADMIN_HOST>` (host mode); admits only `OPENCTEM_ADMIN_ALLOWED_CIDRS`; proxies to `OPENCTEM_CONSOLE_UPSTREAM`. The main site answers 404 for `/api/v1/admin` (`admin/on.tenant`). |
| Console API listener | `ADMIN_LISTEN_ADDR` (Compose: `<api>:8081`) | Serves only `/api/v1/admin` and `/health`; the main listener answers 404 for the console API. |
| API planes | `OPENCTEM_PLANE=all\|tenant\|admin` | One image: `all` for self-host; `tenant` (no console routes, no console credentials, the background work) and `admin` (only the console API, console database role, no background work) for a hosted deployment. |
| Console database role | `DB_ADMIN_USER` ([database roles](../deployment/database-roles.md)) | Writes the administrators, console sessions and platform identity provider; the app role only reads them. |

The sensor protocol's internal mTLS listener is `api:9443`; sensors reach it
only through the gateway's port 443 (ALPN routing on that listener alone), so
port 8443 means only the console.

## Navigation

The sidebar (`web/console/src/features/admin-console/config/admin-nav.ts`,
also the command palette's index) groups the pages by what an operator is
doing:

| Group | Pages |
|-------|-------|
| (top) | Overview |
| Customers | Organizations, Users, Access requests, Sign-ups, Support access |
| Scanning | Scan approval, Platform scanning (policy, fleet, queue, zones, egress, anomalies), Target mappings, Content packs, Content catalog, Threat intelligence |
| Security | Administrators, Sessions, Approvals, Admin sign-in, Admin activity |
| Settings | Configuration, Sign-up, Limits, CAPTCHA, E-mail, Legal, Announcements, Alerts, AI provider, AI applications |
| Monitoring | Health (services, storage, backup, certificates, schema, version, queues, sensors, jobs), Software updates |

The administrator's own security keys open from the sidebar footer, next to
their name (the palette still finds them). Pages are listed by the
administrator's own role, not the session's acting one: a super admin acting
read-only sees every page, and a page that needs more shows "Elevate to see
this page" with the elevate dialog one click away
(`RoleRequiredNotice`). An administrator whose own role is too low is told
which role it takes. The API enforces the acting role either way.

The Overview's "Needs attention" list includes the installation's own state
from the Health page: a service that does not answer, a volume below 20%
(warning) or 10% (critical) free, a failed, stale or unreported backup, a
certificate close to expiry, and a newer release (a warning when it fixes
security advisories).
Suspending an organization and blocking an account (the console's kill
switches): [organization-suspension.md](organization-suspension.md).

## Users and the content catalog

Customers > Users (`GET /api/v1/admin/platform-users`, operations admin and
up) lists every account newest first with state tabs (all, active, not
verified, locked, blocked, no MFA, platform admins) and their counts, an
optional search (email, name or id) and pagination. The list is the least
personal data that tells accounts apart: email, state flags, sign-in method,
number of organizations, last sign-in and creation date; the name, failed
sign-ins, block reason, memberships and sessions are on the account's page,
whose viewing is audited. Every list view writes an admin audit row
(`platform_user.list`, with the state, search and page).

Scanning > Content catalog (`/api/v1/admin/content-catalog`, any role reads)
shows the instance catalog organizations install from: its trust state (the
trust roots come from `CONTENT_TRUST_ROOT_KEY_IDS` on the server and are shown
read-only: a console session cannot trust new content), its packages and
versions, and the actions a super admin takes with a reason and a step-up:
import a signed bundle, publish an instance package, revoke a version. The
listing reads the instance catalog only, never an organization's private
packages or installations. The program feed admin routes were removed
(no console page used them).

## Configuration page

Settings > Configuration (`GET /api/v1/admin/configuration`, any role,
`internal/app/configoverview`) lists the operator settings: the ones the
console manages (applied without a restart, with who changed them and when,
and a link to the page that changes them) and the main server settings
(environment or installer, restart needed), each with its source: set in the
console, set on the server, or the built-in default. A secret (CAPTCHA keys,
AI provider keys, the audit stream address) is reported only as set or not
set. Where the environment value bounds a console setting (`SIGNUP_MODE`,
`VERSION_CHECK_ENABLED=false`) the row says so: the console may tighten it,
never loosen it. Where a set environment variable pins a console setting
(the CAPTCHA keys, the deployment region, the platform AI keys) the row says
"locked by the server configuration" and names it. Rows marked "Moving to the
console" are server settings planned to become console settings.

What stays on the server by design: database and Redis credentials, the
encryption, fingerprint and session keys, listen addresses, trusted proxies,
the console's allowed networks (a ceiling), the API plane, trust roots of
signed content and sensor certificates, the storage backend, the admin audit
stream and retention, backups and the host firewall. A stolen console
session must not be able to read a secret, redirect evidence or audit, or
widen who can reach the console.

## Settings moved from the environment

These settings used to need a server edit and a restart; they are now
console settings (RFC-079), stored in `platform_settings`, read through a
15-second cache so a change applies on every replica without a restart
(`internal/app/consolesetting`). Secrets are encrypted with
`APP_ENCRYPTION_KEY` and write-only: reads say "set" and who changed them
when, never the value, and neither the audit log nor the notice carries it.
Guarded settings need a super admin, a fresh confirmation (a code or a
security key, never the step-up window), a reason, a critical admin audit row
with the old and new values, and a notice to every administrator (e-mail and
the alert webhook).

| Setting | Page | API | Environment | Guard |
|---|---|---|---|---|
| CAPTCHA (Turnstile site key and secret), with "check the secret key" | Settings > CAPTCHA | `/admin/settings/captcha`, `/verify` | `CAPTCHA_TURNSTILE_SECRET` + `_SITE_KEY` lock it | guarded |
| Deployment region, once, before the first organization (the platform's system tenant does not count) | Settings > Configuration | `/admin/settings/region` | `DEPLOYMENT_REGION` locks it | guarded; immutable once set |
| Default storage quota per organization (an organization's `storage_mb` limit wins; 0 = no quota) | Settings > Limits | `/admin/settings/storage-quota` | `STORAGE_TENANT_QUOTA_MB` is the default until the console stores one | super admin + step-up, audited |
| Alert webhook (HTTPS only, SSRF-guarded, optional HMAC signature), with "send a test alert" | Settings > Alerts | `/admin/settings/alerts`, `/test` | none (the kit's host probes stay host-side) | guarded; the previous receiver is told first |
| Platform AI provider, model and key, off by default, with "test the key" | Settings > AI provider | `/admin/settings/ai`, `/test` | any of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` locks it | guarded |

How each applies without a restart:

- CAPTCHA: one verifier (`platformcaptcha.Service`) serves registration,
  request access and the tenant and console sign-ins; it is asked only while
  keys are configured. A stored secret that no longer decrypts keeps the
  CAPTCHA on and refuses every token (fail closed). In production with
  `SIGNUP_MODE=open` and no `SIGNUP_CAPTCHA` waiver, open sign-up is closed
  at runtime until a CAPTCHA is configured (it used to refuse to start).
- Region: new organizations read it at creation; the insert also reads the
  stored value itself, so another replica's stale cache cannot create an
  organization without it. Setting it holds a lock on the organization table,
  so a concurrent organization creation cannot slip in.
- Storage quota: checked per upload; an unreadable quota refuses the upload.
- Alert webhook: the system watch and the setting notices fan out to e-mail
  and the webhook. The address is treated as a credential (only its host is
  shown); delivery never follows the address into a log or error.
- AI provider: the AI client reads the console provider per request when no
  environment key is set; platform mode is refused with a clear message
  (`AI_PLATFORM_NOT_CONFIGURED`) until a provider is on. A provider sends
  nothing by itself: each organization turns AI triage on in Settings > AI
  ([AI triage](ai-triage.md)).

## Installer settings

The same four settings in every installer (Compose and `setup.sh`, the Helm
chart, the Ansible kit): mode (`port` | `host` | `off`), host name, port
(default 8443) and client networks (private by default). Host mode is the
recommended production setup. Details: [Docker deployment](../deployment/docker.md#platform-console).

## Security controls

- Separate origin and process: the browser keeps tenant pages from reading
  console responses; the console bundle holds no tenant code and the tenant
  bundle no console code (ESLint import rules, `web/console/src/__tests__/app-split.test.ts`).
- Strict console headers: a nonce CSP with `frame-ancestors 'none'`,
  `base-uri 'none'`, `form-action 'self'`, `connect-src 'self'` and no
  third-party script; COOP and CORP `same-origin`; `Origin-Agent-Cluster`;
  `Referrer-Policy: no-referrer`; `Cache-Control: no-store`.
- CSRF: every write must carry the console's own `Origin` and its token,
  which is bound to the session (HMAC of the session secret under a key
  derived from `AUTH_JWT_SECRET`) and kept only in memory by the console.
- Pre-session cookie: the console's page cookie for the sign-in steps is
  `console_csrf`, not the tenant site's `csrf_token`: cookies ignore ports,
  so in port mode the two sites would otherwise overwrite each other's token.
  The console proxy refuses a sign-in step that echoes only `csrf_token`.
- Sessions: at most three verified sessions per administrator (opening a
  fourth ends the oldest and writes `console.session_evicted`);
  server-side, 15 minutes idle, 8 hours at most; the console's own
  sign-in and second factor (TOTP or security keys), step-up on protected
  actions, time-boxed elevation, the append-only hash-chained audit log.
  Reads the console makes on its own (page refreshes while nobody uses the
  tab) carry `X-Admin-Background: 1` and do not count as activity, so an
  unattended tab signs out after the idle timeout. A password reset or
  change, or a two-step reset, of the administrator's account ends its
  console sessions.
- Write-ahead audit: before a super administrator's write runs (any
  non-read request whose acting role is super_admin), the API writes one
  `admin.write_started` row (method, path, redacted body) in the request. If
  that row cannot be written the request is refused with 503
  `AUDIT_UNAVAILABLE` and nothing changes; the per-route outcome rows are
  written as before. With `MANAGED_SERVICE=true` in production the API does
  not start without the off-box audit sink (`ADMIN_AUDIT_SINK`). Request
  bodies are redacted by key: any key ending in `secret`, `password`, `_key`
  or `_token` (any case), and `code`, `totp`, `recovery_code`,
  `recovery_codes`.
- Administrator accounts stay off the main site: the account an administrator
  signs in with is refused on the tenant site (password, second-factor
  completion, refresh-token exchange, social and organization SSO sign-in).
  The answer is the wrong-password one, with no session and no cookie, and a
  WARN line with `alert=platform_admin_main_site_sign_in` is logged. The
  console's own password check is a separate path and is unaffected.
- Roster notices: every change to the administrators (added, role or state
  changed, removed, sign-in reset, identity-provider binding removed), the
  administrators' identity provider or the security-key policy is emailed to
  every other active administrator and logged with
  `alert=admin_roster_change`.
- Four-eyes approvals (see the section below): the actions that hand over or
  loosen control of the platform need a second super admin.
- Network: private client networks by default at the gateway and the API;
  optional `OPENCTEM_ADMIN_BIND` to publish the console port on one interface.

## Four-eyes approvals

Shipped (design: [RFC-022 revision 24](../rfcs/RFC-022-platform-admin-console.md#revision-24-four-eyes-approvals)).

| Protected action | When it needs a second super admin |
|---|---|
| Make a super admin | a new super admin, a promotion or reactivation to an active super admin, or the break-glass marker removed |
| Remove a super admin | an active super admin demoted, deactivated, marked break-glass or removed |
| Stop requiring security keys | the security-key policy goes from on to off |
| Remove or relax the administrators' identity provider | removed, switched off, or no longer required |
| Change the administrators' identity provider or the second factor it is trusted for | a new issuer or client id on an existing provider, or any trusted ACR/AMR value not trusted before (also on a first configuration); the target is the new issuer, client and trusted values |
| Reset another administrator's console second factor | always (their next sign-in enrolls a new factor) |
| Open sign-up | the stored sign-up policy opens wider than before |
| Re-sign an organization's audit chain | always |

How it works for the administrators:

1. Super admin A tries the action. The console answers that another super
   admin must approve and opens a dialog: A gives a reason and asks
   (step-up). The other administrators are e-mailed.
2. Super admin B opens Security > Approvals and approves with a fresh code or
   security-key confirmation (or rejects). B can never be A, and a
   break-glass account never approves.
3. A repeats the action within 24 hours of asking. The approval is bound to
   A, the action and its exact target (the e-mail address, administrator or
   organization), and works once.

With only one named super admin (break-glass accounts do not count), the
actions run on the super admin's own step-up, each recorded as critical
(`approval.single_admin`) and e-mailed to every administrator; the
Approvals page explains how to add a second super admin. Once two exist,
removing either needs the other's approval. If the other super admin is
unavailable, end their console sessions from the console and change the
roster with `bootstrap-admin` on the server. Resetting an administrator's
console second factor needs another super admin too: an administrator who lost
their authenticator signs in with a recovery code, or the operator re-creates
the account with `bootstrap-admin -force` on the server.
That command is not a silent side door: every administrator it creates,
replaces (`-force`, `-force-backup`) or links (`-link`) is written in the same
transaction as a high-severity entry in the administrators' audit log
(`admin.created`, `admin.replaced`, `admin.relinked`; actor `bootstrap-admin`,
with the OS user and host), and every other active administrator gets the
roster-change e-mail. `-force` replaces only the named administrator, keeps
its role unless `-role` is given, refuses to bring back an inactive one
without `-role`, refuses to leave no active super admin, and asks for the
email to be typed back (or `-yes`).

IdP binding: the first platform IdP sign-in of an unbound administrator (matched
by verified e-mail) binds the identity only after that administrator proves
their own console second factor on the pending session; a trusted ACR/AMR
value skips the console factor only for an identity bound that way. An
unbound administrator with no console factor yet (never signed in, or reset)
is refused on the IdP while the password path is open: they enroll on the
password path first. Only while "require IdP" closes the password path is the
IdP their sole first factor and the console factor enrolled after it. Whoever
can mint an IdP token carrying another administrator's e-mail therefore cannot
sign in as them and approve their own requests.

API: `GET /api/v1/admin/approvals`, `POST /api/v1/admin/approvals`
(step-up), `POST /api/v1/admin/approvals/{id}/approve` (fresh step-up),
`/reject` (step-up), `/cancel` (requester); all super admin only. A protected
route refuses with `428 SECOND_APPROVAL_REQUIRED` and `details` naming the
action, the target and the caller's open request. Table `admin_approvals`
(migration `002914`), owned by the console's database role.

## Tests

- `web/console/src/__tests__/app-split.test.ts`: route lists of both apps, no
  cross-imports.
- `web/console/src/__tests__/console-csrf-cookie.test.ts`: the console sets
  `console_csrf` and never `csrf_token`.
- `api/tests/unit/auth_platform_admin_main_site_test.go`: an administrator
  with the right password gets the wrong-password answer and no cookie on the
  main site; the console password check still works.
- `api/internal/infra/http/middleware/admin_audit_test.go`: the write-ahead row
  is written first, and a failing audit write refuses the request.
- `web/console/src/__tests__/console-origin.test.ts`: a write from the tenant
  origin (same host, other port), another port or a sibling host is refused
  before any API call.
- `api/internal/infra/http/middleware/admin_auth_test.go`: the CSRF token is
  bound to the session (a planted cookie is refused).
- `api/internal/infra/http/admin_listener_test.go`: listener and plane splits.
- `api/deploy/gateway/smoke-test.sh`: both sites, the allow-list, the console
  port checks.
