# Docker and Sentry (development)

Developer notes for running the web console in Docker and for error reporting.
To deploy OpenCTEM, use the published images and the guides at
[docs.openctem.io/install](https://docs.openctem.io/install/).

## Docker files

| File | Purpose |
|---|---|
| `web/Dockerfile` | Multi-target build on `node:26-alpine`: `development` (hot reload), `builder`, `production` (standalone output, user `nextjs`, health check on `/api/health`) |
| `web/docker-compose.yml` | Development: service `nextjs`, source mounted, `WATCHPACK_POLLING=true`, port `${UI_PORT:-3000}` |

The supported production layout is the platform stack in
`api/deploy/docker-compose.yml` (gateway, web, API, PostgreSQL, Redis) or the
all-in-one image; `web/docker-compose.yml` is for development only.

## Development in Docker

```bash
cd web
cp .env.example .env.local      # set BACKEND_API_URL to an API reachable from the container
docker compose up --build       # http://localhost:3000
docker compose logs -f nextjs
docker compose exec nextjs sh
docker compose down
```

Rebuild (`--build`) after changing `package.json`. If hot reload stops picking up
changes, check the bind mount and that `WATCHPACK_POLLING=true` is set.

Health check: `curl http://localhost:3000/api/health` answers
`{"status":"ok","timestamp":"...","environment":"..."}`.

## Building the production image

```bash
cd web
docker build --target production -t openctem-web:local .
```

`NEXT_PUBLIC_*` values are inlined at build time (see
[ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md)). Release images
(`ghcr.io/openctemio/openctem-web`) are built by
`.github/workflows/docker-publish.yml`.

## Sentry

`@sentry/nextjs` is a dependency, but error reporting is **not wired**:
`sentry.{client,server,edge}.config.ts` are no-op stubs (`export {}`), the Sentry
block in `instrumentation.ts` `register()` is commented out, and `next.config.ts`
does not use `withSentryConfig`. Setting `NEXT_PUBLIC_SENTRY_DSN` alone does
nothing.

To enable it in a build of your own:

1. Replace the stub `sentry.*.config.ts` files with `Sentry.init({ dsn: process.env.NEXT_PUBLIC_SENTRY_DSN, ... })`.
2. Uncomment the initialization in `instrumentation.ts`.
3. Wrap the exported config in `next.config.ts` with `withSentryConfig(...)`.
4. Set `NEXT_PUBLIC_SENTRY_DSN` (and, for source maps, `SENTRY_AUTH_TOKEN`,
   `SENTRY_ORG`, `SENTRY_PROJECT`) and rebuild.
5. Throw a test error from a component and confirm the event arrives.
