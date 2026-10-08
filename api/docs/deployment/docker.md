# Docker (development)

This page covers the API's Docker files for development and image builds. To
deploy OpenCTEM with Docker Compose or the all-in-one image, follow
[docs.openctem.io/install](https://docs.openctem.io/install/).

> **Migrations:** auto-migration is a development-only convenience. In
> production the API does not migrate: a one-shot `migrate` service applies
> migrations before the API starts, and the API refuses to start while the schema
> is behind. See [Safe Deploy & Migrations](safe-deploy-and-migrations.md).

## Files

| File | Purpose |
|------|---------|
| `api/Dockerfile` | Multi-target build: `development` (Air, Delve, migrate), `base` and `builder`, `production` (Alpine, non-root user `openctem`) |
| `api/Dockerfile.migrations`, `Dockerfile.seed`, `Dockerfile.admin-cli` | The `migrations`, `seed` and `admin-cli` release images |
| `api/docker-compose.yml` | Base services: PostgreSQL 17 and Redis 7 (ports published for development) |
| `api/docker-compose.dev.yml` | The API in the `development` target, source bind-mounted |
| `api/docker-compose.prod.yml` | The API alone from a published image, with `db-roles` and `migrate` one-shot services |
| `api/deploy/docker-compose.yml` | The full production stack: gateway (one HTTPS port), web, API, PostgreSQL and Redis with TLS |
| `api/deploy/gateway/` | Gateway Caddyfile, TLS modes, entrypoint and `smoke-test.sh`. `planes.caddy` is generated from the API's plane table: do not edit it by hand |
| `deploy/allinone/` | The all-in-one image (`ghcr.io/openctemio/openctem`): API, web and gateway in one container |

## Development environment

```bash
cd api
make docker-dev        # foreground; make docker-dev-d for background
# same as:
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

The `development` container (`scripts/dev-entrypoint.sh`):

1. waits for PostgreSQL,
2. applies migrations (`migrate -path /app/migrations up`) unless
   `AUTO_MIGRATE=false`,
3. starts Air for hot reload.

The source tree is bind-mounted at `/app`; ports are 8080 (HTTP), 9090 (gRPC) and
2345 (Delve). Logging is `debug`/`text`, authentication is `AUTH_PROVIDER=local`.

Migrations by hand:

```bash
make docker-migrate-up        # uses the migrate/migrate image and DATABASE_URL
make docker-migrate-down
make docker-migrate-version
```

### Debugging with Delve

Attach a debugger to port 2345, for example VS Code:

```json
{
  "name": "Docker: Attach",
  "type": "go",
  "request": "attach",
  "mode": "remote",
  "port": 2345,
  "host": "127.0.0.1"
}
```

## Building images

```bash
make docker-build        # production target, tagged openctem:latest
make docker-build-dev    # development target

# From the repository root: API, web and the all-in-one image, tagged :local
make allinone
```

Release images are built by `.github/workflows/docker-publish.yml` from a
`vX.Y.Z` tag: `ghcr.io/openctemio/openctem-api`, `openctem-web`, `openctem`
(all-in-one), `migrations`, `seed` and `admin-cli`.

## Production compose files

`api/docker-compose.prod.yml` runs a published API image with its `migrate`
one-shot service; the API starts only after migrations succeed
(`depends_on: migrate: { condition: service_completed_successfully }`). Keep
`MIGRATIONS_VERSION` equal to `API_VERSION`.

If a migration fails midway, `golang-migrate` marks `schema_migrations.dirty` and
the API refuses to start. Recovery is in the
[runbook](safe-deploy-and-migrations.md#dirty-migration-recovery). Never set
`SKIP_SCHEMA_CHECK=true` in production.

The complete production stack (`api/deploy/docker-compose.yml`), its environment
variables and TLS modes are documented for operators at
[docs.openctem.io/install](https://docs.openctem.io/install/).

## Make targets

```bash
make docker-down         # stop the dev and prod compose stacks
make docker-logs         # follow logs
make docker-logs-app     # API logs only
make docker-ps           # running containers
make docker-clean        # remove containers, volumes and local images
make docker-psql         # psql shell in the postgres container
```

## Troubleshooting

- **Hot reload does not pick up changes:** `.air.toml` uses polling
  (`poll = true`, `poll_interval = 500`); check the bind mount works on your
  host.
- **Stale build cache:**
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml build --no-cache`.
- **Health:** `curl http://localhost:8080/health`,
  `docker compose exec postgres pg_isready -U openctem`,
  `docker compose exec redis redis-cli ping`.
