# Platform console: its own service, site and plane

Design: [RFC-022](../rfcs/RFC-022-platform-admin-console.md), revisions 20
and 21. This page is how the platform administration console is built and
deployed today.

## Components

| Part | Where | What it does |
|------|-------|--------------|
| Console app | `web/console/` (Next.js), image `ghcr.io/openctemio/openctem-console` | The console's pages at the root of its site (`/`, `/login`, `/organizations`, `/users`, `/security/…`, `/operations`, `/system/…`, `/scanning/…`, `/requests`), its API proxy `/api/v1/admin/*` and `/api/health`. Shares `web/`'s packages and imports shared code from `web/src`; contains no tenant route. |
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
| Customers | Organizations, Users, Access requests, Support access |
| Scanning | Scan approval, Platform scanning, Shared sensors, Target mappings, Content packs, Content catalog, Threat intelligence |
| Security | Administrators, Sessions, Admin sign-in, Admin activity |
| Settings | Sign-up, Limits, E-mail, Legal, Announcements, AI applications |
| Monitoring | Health, System, Software updates |

The administrator's own security keys open from the sidebar footer, next to
their name (the palette still finds them). Pages are listed by the
administrator's own role, not the session's acting one: a super admin acting
read-only sees every page, and a page that needs more shows "Elevate to see
this page" with the elevate dialog one click away
(`RoleRequiredNotice`). An administrator whose own role is too low is told
which role it takes. The API enforces the acting role either way.

The Overview's "Needs attention" list includes the installation's own state
from the System page: a service that does not answer, a volume below 20%
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
never loosen it. Rows marked "Moving to the console" are server settings
planned to become console settings.

What stays on the server by design: database and Redis credentials, the
encryption, fingerprint and session keys, listen addresses, trusted proxies,
the console's allowed networks (a ceiling), the API plane, trust roots of
signed content and sensor certificates, the storage backend, the admin audit
stream and retention, backups and the host firewall. A stolen console
session must not be able to read a secret, redirect evidence or audit, or
widen who can reach the console.

## Settings

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
- Sessions: server-side, 15 minutes idle, 8 hours at most; the console's own
  sign-in and second factor (TOTP or security keys), step-up on protected
  actions, time-boxed elevation, the append-only hash-chained audit log.
  Reads the console makes on its own (page refreshes while nobody uses the
  tab) carry `X-Admin-Background: 1` and do not count as activity, so an
  unattended tab signs out after the idle timeout. A password reset or
  change, or a two-step reset, of the administrator's account ends its
  console sessions.
- Roster notices: every change to the administrators (added, role or state
  changed, removed, sign-in reset, identity-provider binding removed), the
  administrators' identity provider or the security-key policy is emailed to
  every other active administrator and logged with
  `alert=admin_roster_change`.
- Network: private client networks by default at the gateway and the API;
  optional `OPENCTEM_ADMIN_BIND` to publish the console port on one interface.

## Tests

- `web/console/src/__tests__/app-split.test.ts`: route lists of both apps, no
  cross-imports.
- `web/console/src/__tests__/console-origin.test.ts`: a write from the tenant
  origin (same host, other port), another port or a sibling host is refused
  before any API call.
- `api/internal/infra/http/middleware/admin_auth_test.go`: the CSRF token is
  bound to the session (a planted cookie is refused).
- `api/internal/infra/http/admin_listener_test.go`: listener and plane splits.
- `api/deploy/gateway/smoke-test.sh`: both sites, the allow-list, the console
  port checks.
