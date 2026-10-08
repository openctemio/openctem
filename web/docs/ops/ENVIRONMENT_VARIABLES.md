# Web Console Environment Variables

The variables the web console (`web/`) reads. [`.env.example`](../../.env.example)
is the template; `src/lib/env.ts` holds the typed accessors and defaults. Operator
configuration of a whole installation is documented at
[docs.openctem.io/configuration](https://docs.openctem.io/configuration/).

## `NEXT_PUBLIC_*` vs server-only

| Property | `NEXT_PUBLIC_*` | Server-only (no prefix) |
|---|---|---|
| Visible to | Browser and server | Server only |
| Bundled | Inlined into client JavaScript at **build** time | Read at run time |
| Use for | Non-secret display and behaviour settings | Secrets and internal URLs |

Never put a secret in a `NEXT_PUBLIC_*` variable.

## How the browser reaches the API

The browser never reads an API URL. Client code calls the relative path
`/api/v1/*`; the console's same-origin proxy (`src/app/api/v1/[...path]/route.ts`)
reads the httpOnly session cookie and forwards the call to `BACKEND_API_URL` with
the token as a bearer header. The WebSocket also opens on the console's own
origin (`/api/v1/ws`) and is proxied to the API. So the API port never has to be
reachable from browsers.

## Server-only variables

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_API_URL` | `http://localhost:8080` | Where the console's server reaches the API (for example `http://api:8080` in Compose). `localhost` is rewritten to `127.0.0.1`. |
| `API_TIMEOUT` | `30000` | Request timeout to the API, in milliseconds |
| `CSRF_SECRET` | (empty) | Secret for CSRF tokens; at least 32 characters (`npm run generate-secret`). A warning is logged when missing or short. |
| `SECURE_COOKIES` | `true` | `Secure` flag on cookies. Set `false` only for local plain-HTTP development. |
| `TRUST_PROXY_HEADERS` | `false` | Forward `X-Real-IP` / `X-Forwarded-For` to the API (organization IP allowlists). Set `true` only when a reverse proxy in front of the console overwrites these headers. |
| `COOKIE_MAX_AGE` | `604800` | Refresh-token cookie lifetime in seconds (7 days) |
| `ENABLE_TOKEN_REFRESH` | `true` | Automatic access-token refresh |
| `TOKEN_REFRESH_BEFORE_EXPIRY` | `300` | Refresh this many seconds before the access token expires |

## Public variables (`NEXT_PUBLIC_*`)

| Variable | Default | Purpose |
|---|---|---|
| `NEXT_PUBLIC_APP_URL` | `http://localhost:3000` | The console's public URL (links, redirects, CSP `connect-src`) |
| `NEXT_PUBLIC_APP_NAME` | `OpenCTEM` | Product name shown in the UI |
| `NEXT_PUBLIC_APP_DESCRIPTION` | | Page description metadata |
| `NEXT_PUBLIC_TERMS_URL`, `NEXT_PUBLIC_PRIVACY_URL` | (empty) | Legal links on the sign-in and register pages; empty shows no notice |
| `NEXT_PUBLIC_WS_BASE_URL` | (empty) | WebSocket host override. Leave empty; set only for a same-site host that receives the session cookie |
| `NEXT_PUBLIC_AUTH_COOKIE_NAME` | `auth_token` | Access-token cookie name |
| `NEXT_PUBLIC_REFRESH_COOKIE_NAME` | `refresh_token` | Refresh-token cookie name (must match the API) |
| `NEXT_PUBLIC_COOKIE_DOMAIN` | (unset) | Cookie `Domain` attribute, when cookies must span subdomains |
| `NEXT_PUBLIC_ENABLE_SIDEBAR_BADGES` | `false` | Show live counts in the sidebar (extra API calls on page load) |
| `NEXT_PUBLIC_SENTRY_DSN` | (empty) | Sentry error reporting, see [DOCKER_SENTRY_SETUP.md](DOCKER_SENTRY_SETUP.md) |

`NEXT_PUBLIC_APP_VERSION` and `NEXT_PUBLIC_APP_COMMIT` are set by the image build.

## Build and development only

| Variable | Purpose |
|---|---|
| `DOCKER_BUILD`, `CI` | Skip the environment check (`validateEnv()`) during image builds and CI |
| `NEXT_ALLOWED_DEV_ORIGINS` | Extra origins allowed to reach `next dev` |
| `ANALYZE` | `true` runs the bundle analyzer (`npm run analyze`) |

## Common mistakes

- Reading a server-only variable in a Client Component: it is `undefined` in the
  browser. Call the API through `/api/v1/*` instead.
- Calling the API host directly from the browser: it bypasses the proxy, the
  session cookie and the CSRF header.
- Changing a `NEXT_PUBLIC_*` value on a running container: it was inlined at build
  time, so the image must be rebuilt.
