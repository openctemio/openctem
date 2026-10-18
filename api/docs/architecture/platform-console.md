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
| Scanning | Scan approval, Platform scanning, Shared sensors, Target mappings, Content packs, Threat intelligence |
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
