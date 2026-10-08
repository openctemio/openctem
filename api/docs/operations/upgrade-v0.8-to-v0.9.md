# Upgrading from v0.8.0 to v0.9.0

> **Applies to:** a production installation running OpenCTEM **v0.8.0**
> (API and web `v0.8.0` from the former `openctemio/api` and `openctemio/ui`
> repositories, Helm chart `openctem-0.4.1`, database migration **000224**).
>
> **Target:** the next release from the `openctemio/openctem` monorepo.
> The release train proposes **v0.9.0** for it
> (`.github/scripts/release/next-version.sh`: breaking changes since v0.8.0).
> If the release is tagged with another number, read "v0.9.0" in this guide as
> that number; nothing else changes.
>
> **Proven path:** every step below was run on a scratch copy of a v0.8.0
> database (built from v0.8.0's own migrations, filled through the v0.8.0 API
> and its sensor ingest, plus a 630 MB bulk copy) up to the new release's
> migrations, then the new API was started against it and checked (sign-in,
> data, sensors). The timings in this guide come from those runs.

v0.9.0 is a large release: about 1,700 commits and 210 database migrations
since v0.8.0. Plan a maintenance window, read the
[pre-flight checklist](#2-pre-flight-checklist) a few days before it, and run
the [inventory queries](#25-run-the-inventory-queries) first: several changes
need a decision from you or from your organization owners.

## Contents

1. [The upgrade at a glance](#1-the-upgrade-at-a-glance)
2. [Pre-flight checklist](#2-pre-flight-checklist)
3. [Images, Compose, Helm and configuration](#3-images-compose-helm-and-configuration)
4. [Database migration path](#4-database-migration-path)
5. [What the data migrations change](#5-what-the-data-migrations-change)
6. [API and integration changes](#6-api-and-integration-changes)
7. [Permissions and roles](#7-permissions-and-roles)
8. [Sensors and CI](#8-sensors-and-ci)
9. [Sign-in, SSO and identity provider changes](#9-sign-in-sso-and-identity-provider-changes)
10. [Upgrade procedure](#10-upgrade-procedure)
11. [Post-upgrade verification](#11-post-upgrade-verification)
12. [Rollback](#12-rollback)
13. [What's new for your users](#13-whats-new-for-your-users)
14. [Appendix: inventory queries](#appendix-inventory-queries)

---

## 1. The upgrade at a glance

| | |
|---|---|
| **Downtime** | Required. The API and web are stopped for the whole upgrade; there is no rolling upgrade from v0.8.0 (tables are renamed). Measured migration time: seconds on a small database, about 1.5 minutes on a 630 MB database (see [4.4](#44-how-long-it-takes)). Plan **60 minutes** of window for a database up to a few GB, including backup, image pulls, checks and sign-in tests. |
| **Database** | Two hops. v0.9.0 starts its migrations from one baseline file (`001146_baseline`, [RFC-053](../rfcs/RFC-053-migration-baseline.md)) and refuses a v0.8.0 database without changing it. First apply the migrations of git tag **`pre-baseline-001146`** (000225 → 001146), then the v0.9.0 migrations image (001147 → latest). |
| **PostgreSQL** | **17 or later** is required (migration 000257 uses PostgreSQL 17 syntax). The v0.8.0 Compose files shipped `postgres:17-alpine`. |
| **Images** | New names: `ghcr.io/openctemio/openctem-api`, `openctem-web`, all-in-one `openctem`; `migrations`, `seed`, `admin-cli` keep their names. One tag (`v0.9.0`) for all of them. |
| **Sensors** | Sensor protocol v1 (`/api/v1/agent/*`) is removed: v0.8.0-era agents stop working at the upgrade. Move sensors to **v0.9.1** before the window (it works with both versions), then to **v0.11.0** after it. CI scanning moves to `openctemio/ci` with OIDC. |
| **Integrations** | Many routes were removed or renamed **without aliases** ([section 6](#6-api-and-integration-changes)). Scripts and API clients must be updated. |
| **Access** | Members who are in no access group **see no assets or findings** after the upgrade ([5.1](#51-data-visibility-and-access)). Sensitive actions need a recent sign-in (step-up). |
| **Irreversible** | Several data migrations cannot be undone (listed in [12](#12-rollback)). The way back is the pre-upgrade backup. |

Order of work:

1. A few days before: inventory queries, decisions, configuration drafts, a
   restore test, a rehearsal on a copy of production, sensors to v0.9.1.
2. In the window: stop API and web → back up → hop 1 → hop 2 → start the new
   API and web → create the platform administrators → verify.
3. After: sensors to v0.11.0, update API clients and CI pipelines, tell users
   what changed.

---

## 2. Pre-flight checklist

### 2.1 Versions

Run against the production database (read-only):

```sql
SHOW server_version;                         -- 17.x or later
SELECT version, dirty FROM schema_migrations; -- expect 224 | f
```

- `dirty = t`: a previous migration failed half-way. Fix that first (see
  [Safe deploy → dirty migrations](../deployment/safe-deploy-and-migrations.md)).
- A version below 224: you are not on v0.8.0. Upgrade to v0.8.0 first, or
  accept that the older releases' changes run too (migrations are applied in
  order; the inventory queries are written for the v0.8.0 schema).
- PostgreSQL 15 or 16: upgrade PostgreSQL to 17 first (`pg_upgrade`, or dump
  and restore into a PostgreSQL 17 server), on v0.8.0, then come back here.
- Redis 7 (`redis:7-alpine`), unchanged.

### 2.2 Backup and restore test

The backup is the rollback plan. Take a full logical backup and **prove you
can restore it** before the window:

```bash
# Compose (service name `postgres`, as in the v0.8.0 files)
docker compose exec -T postgres pg_dump -U openctem -d openctem --format=custom \
  > openctem-v0.8.0-$(date +%Y%m%d-%H%M).dump

# Restore test into a throwaway PostgreSQL 17 (never into production)
docker run -d --name restore-test -e POSTGRES_PASSWORD=x postgres:17-alpine
docker exec restore-test sh -c 'until pg_isready -U postgres; do sleep 1; done'
docker exec restore-test createdb -U postgres openctem
docker exec -i restore-test pg_restore -U postgres -d openctem --no-owner < openctem-v0.8.0-*.dump
docker exec restore-test psql -U postgres -d openctem -c 'SELECT version, dirty FROM schema_migrations;'
# keep it for the rehearsal below, then: docker rm -f restore-test
```

Also back up the root `.env`/env files and your Helm values: `APP_ENCRYPTION_KEY`
must stay exactly the same (it decrypts integration credentials, TOTP secrets
and sensor key peppers).

**Rehearse on the restored copy.** Run [section 4](#4-database-migration-path)
against the restore-test database (`--network container:restore-test` and
`postgres://postgres:x@localhost:5432/openctem?sslmode=disable` in the
`docker run` commands): you get your own migration durations and
see any data problem before the window.

### 2.3 Disk

Keep at least 20 % free on the database volume and on the Docker data root.
The upgrade needs room for the backup (about 5 % of the database size in
custom format, measured), the new images (about 1.5 GB with the sensor) and
temporary table rewrites (up to the size of `assets` + `findings`).

### 2.4 Decisions to make before the window

| Decision | Default in v0.9.0 | Keep v0.8.0 behaviour with |
|---|---|---|
| Who creates organizations | platform administrator only (`TENANT_CREATION_MODE=admin_only`) | `TENANT_CREATION_MODE=self_service` |
| Self-registration | off (`AUTH_ALLOW_REGISTRATION=false`) | `AUTH_ALLOW_REGISTRATION=true` (open instances only) |
| Members without an access group | see nothing | put them in access groups, or give their role "full data access" |
| Who may resolve findings | `findings:verify` holders (owner, admin) | add `findings:verify` to a custom role |
| Compose layout | single HTTPS port stack (`api/deploy/docker-compose.yml`) | keep the two Compose files ([3.2](#32-docker-compose)) |
| Least-privilege database roles | optional | single role (nothing to do) |
| Platform administrators | two new sign-in accounts (primary + break-glass) | `bootstrap-admin -link` for a v0.8.0 administrator |

### 2.5 Run the inventory queries

The [appendix](#appendix-inventory-queries) has a read-only SQL file, checked
against the v0.8.0 schema. Save its output; it tells you which changes apply
to you and what to compare after the upgrade:

```bash
docker compose exec -T postgres psql -U openctem -d openctem -f - < v0.9-inventory.sql > inventory-before.txt
```

| Query | If it returns rows / non-zero |
|---|---|
| B1–B4 | **Blocking.** The upgrade stops at that migration. Fix the rows first (see each query's comment). |
| C1 | These members will see no assets or findings: add them to access groups (Settings → Teams) or give them a full-data-access role, before or right after the upgrade. |
| C2 | These CI runner agents are deleted. Move those pipelines to OIDC ([8.4](#84-ci-pipelines)). |
| C3 | Declared tool lists are dropped; a sensor gets the tools it reports. Nothing to do. |
| C4 | URL assets become web endpoints under their site; their findings move to the site ([5.2](#52-assets-and-the-web-surface)). Also gives the extra migration time (about 6 ms per URL asset). |
| C5 | HTTP services stored under a broken name (`https:::host`). Rename them after the upgrade ([11](#11-post-upgrade-verification)). |
| C6, C7 | Automations that are switched off or that run no step until saved again ([5.4](#54-automations)). |
| C8 | Scheduled scans without an owner stop running on schedule ([5.3](#53-scans-and-scan-workflows)). |
| C9 | Informational findings lose their SLA deadline ([5.5](#55-findings-severity-and-sla)). |
| C10, C11 | Custom roles and API keys whose permissions are renamed or removed ([7](#7-permissions-and-roles)). |
| C12 | Path exclusions rewritten to host + path prefix; duplicates of one rule merged. |
| C13 | Wildcard scope targets now also cover their apex ([5.1](#51-data-visibility-and-access)). |
| C14 | Outbound webhooks, scope schedules and scan sessions are dropped. Export them now if you need a record. |
| C15 | Platform administrators: all are deactivated and their API keys revoked ([9.1](#91-platform-administrators)). |
| C16–C19 | IP allowlists, allowed domains and "Require 2FA" are enforced; SSO JIT needs a verified domain ([9](#9-sign-in-sso-and-identity-provider-changes)). |
| C20 | Commands in flight are lost when the sensors are replaced. Let them finish. |

### 2.6 Tell people

- Organization owners: members without a team see nothing; resolving a
  finding needs the verify permission; SSO changes go through the platform
  administrator; sensitive actions ask for the password or 2FA code again.
- API and script owners: [section 6](#6-api-and-integration-changes).
- CI owners: CI scanning moves to `openctemio/ci` with OIDC.

---

## 3. Images, Compose, Helm and configuration

### 3.1 Images

| v0.8.0 | v0.9.0 | Notes |
|---|---|---|
| `ghcr.io/openctemio/api` | `ghcr.io/openctemio/openctem-api` | The old name receives identical copies during a transition window. |
| `ghcr.io/openctemio/ui` | `ghcr.io/openctemio/openctem-web` | Same. |
| `ghcr.io/openctemio/migrations` | `ghcr.io/openctemio/migrations` | Entrypoint is now `openctem-migrate` (same arguments; prints instructions when a database is older than the baseline). Runs as uid 65532. |
| `ghcr.io/openctemio/admin-cli` | `ghcr.io/openctemio/admin-cli` | Contains only `bootstrap-admin` (`openctem-admin` and `bootstrap-tenant` are gone). |
| `ghcr.io/openctemio/seed` | `ghcr.io/openctemio/seed` | |
| — | `ghcr.io/openctemio/openctem` | New all-in-one image: API + web + HTTPS gateway. |
| `ghcr.io/openctemio/agent:v0.2.x` | `ghcr.io/openctemio/sensor:v0.11.0` | See [8](#8-sensors-and-ci). |
| `ghcr.io/openctemio/sensor:*-ci` | `ghcr.io/openctemio/ci` | CI moved to the `openctemio/ci` repository. |

Bare Docker Hub names (`openctemio/api`, `openctemio/ui`, `openctemio/migrations`)
in old example files were never published for v0.8.0; use the GHCR names.
All images are signed with cosign (keyless) and have SBOMs on the release.

### 3.2 Docker Compose

The two v0.8.0 repositories are now `api/` and `web/` of
`openctemio/openctem`. You have two options.

**Option A — keep your layout (two Compose projects).** Use
`api/docker-compose.yml` + `api/docker-compose.prod.yml` and
`web/docker-compose.prod.yml` from the `v0.9.0` tag. Changes against the
v0.8.0 files:

- The API no longer publishes ports 8080 and 9090 (`expose: 8080` only). If
  your web container or proxy reached the API through the host port, add an
  override (`ports: ["127.0.0.1:8080:8080"]`) or join both projects to one
  network. Port 9090 (gRPC, metrics) must never be public.
- New volume `api-data:/app/data`: attachments and finding evidence. The root
  filesystem is read-only; without it every upload fails. Back it up with the
  database. (v0.8.0 kept uploads in the container filesystem; they were lost on
  every restart, so there is nothing to copy.)
- New one-shot service `db-roles` (least-privilege database roles). It does
  nothing unless you set `DB_MIGRATE_USER` ([database roles](../deployment/database-roles.md)).
- The web container runs `node server-with-ws.mjs` (WebSocket forwarding), with
  a read-only root filesystem and tmpfs `/tmp` and `/app/.next/cache`. A custom
  `command:` override loses the WebSocket forwarding.
- **Keep the same Compose project name**, so the existing volumes are reused:
  Compose prefixes volumes with the project name (the directory name by
  default). Check with `docker volume ls | grep postgres-data` and pass
  `-p <old project name>` (or `COMPOSE_PROJECT_NAME`) if the directory changed.
- Keep `postgres:17-alpine` for an existing data directory. Do not switch an
  existing volume to the Debian-based `postgres:17` image: the text collation
  changes with the C library (musl → glibc) and text indexes would no longer
  match. `api/docker-compose.prod.yml` defaults to `17-alpine`
  (`POSTGRES_VERSION`).

**Option B — the single HTTPS port stack (`api/deploy/docker-compose.yml`).**
Gateway (Caddy) on one HTTPS port, web, API, migrations, PostgreSQL and Redis
with TLS between them. It is the layout new installations use. Moving to it
means a new stack: finish [section 4](#4-database-migration-path) on your
v0.8.0 stack, take a new `pg_dump` of the migrated database, start the new stack
with an empty database volume up to Postgres only, `pg_restore` the dump, then
start the rest. It needs `OPENCTEM_VERSION`, `OPENCTEM_HOSTNAME`,
`OPENCTEM_PUBLIC_URL`, `DB_PASSWORD`, `REDIS_PASSWORD`, `AUTH_JWT_SECRET`,
`APP_ENCRYPTION_KEY` (same value as before) and `CSRF_SECRET`
(`api/deploy/.env.example`). Sensors then use `https://<hostname>` as `API_URL`.

### 3.3 API environment variables

**The API refuses to start** when one of these is wrong:

| Variable | Change | What to do |
|---|---|---|
| `AGENT_CONFIG_TEMPLATES_DIR`, `AGENT_PUBLIC_API_URL`, `AGENT_KEY_TTL`, `AGENT_LB_*` | Retired; startup fails while any is set (any `APP_ENV`) | Rename to `SENSOR_CONFIG_TEMPLATES_DIR`, `SENSOR_PUBLIC_API_URL`, `SENSOR_KEY_TTL`, `SENSOR_LB_*`. Move custom templates from `configs/agent-templates` to `configs/sensor-templates`. |
| `AUTH_COOKIE_SECURE` | Default `true` outside `APP_ENV=development`; production refuses `false` for every `AUTH_PROVIDER` (v0.8.0 checked only local and hybrid) | Serve over HTTPS. A non-development stack on plain `http://` must set `false` (and is not a production setup). |
| `TENANT_CREATION_MODE` | New; `admin_only` (default) or `self_service`; any other value fails startup | See [2.4](#24-decisions-to-make-before-the-window). |
| `SCOPE_ACTIVE_PROOF` | New; `off`, `platform_sensors`, `all`; any other value fails startup. Unset: `platform_sensors` with `self_service`, else `off` | Leave unset for a single-organization installation. `all` makes every active scan need a DNS-verified domain. |
| `APP_TEMPLATE_SIGNING_KEY` | New, optional; must be a valid key and differ from `APP_ENCRYPTION_KEY` | Recommended: `openssl rand -hex 32`. Unset, it is derived from `APP_ENCRYPTION_KEY`. Sensors pin the public key to run custom templates ([8.3](#83-after-the-upgrade-grants-trust-and-templates)). |
| `APP_ENCRYPTION_KEY_PREVIOUS` | New, optional; old keys during a rotation | Leave empty. See [Rotating APP_ENCRYPTION_KEY](../deployment/encryption-key-rotation.md). |
| `SENSOR_KEY_PEPPER` | New, optional; at least 32 characters when set | Leave empty (derived from `APP_ENCRYPTION_KEY`). |
| `KEYCLOAK_BASE_URL` + `KEYCLOAK_REALM` | With `AUTH_PROVIDER=oidc` or `hybrid` they must form an issuer URL | Check both are set. |
| `STORAGE_PROVIDER` | Only `local`, `s3`, `minio`; `s3`/`minio` need `STORAGE_BUCKET`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY` | Check if you set it. |

Unchanged and still enforced in production: `DB_SSLMODE` not `disable`,
`AUTH_JWT_SECRET` of 64+ characters, `APP_ENCRYPTION_KEY` set, Redis password
of 32+ characters with `REDIS_TLS_ENABLED=true`, no wildcard CORS origin, rate
limiting on, debug off.

**Defaults that changed** (set the old value explicitly to keep it):

| Variable | v0.8.0 | v0.9.0 |
|---|---|---|
| `AUTH_ALLOW_REGISTRATION` | `true` | `false` (an env file copied from the old example that sets `true` keeps registration open) |
| `SSO_ENTRA_DEFAULT_ROLE` | `member` | `viewer` (also the default role of SSO just-in-time users) |
| `SENSOR_KEY_TTL` (was `AGENT_KEY_TTL`) | `0` (never expires) | `2160h`: renewed sensor keys expire after 90 days; sensors renew them on their own |
| `WORKER_HEALTH_CHECK_ENABLED` | `true` | `false` (sensor liveness has its own controller) |
| `CORS_ALLOWED_HEADERS` | included `X-Admin-API-Key` | no longer does (admin API keys are gone) |

**New, optional** (safe defaults; set them when you need them):
`SERVER_TRUSTED_PROXIES` (the web container's address or network: needed for
correct client IPs, login rate limits and IP allowlists), `SCOPE_DENY_EXTRA`
(your own names and ranges that must never be scanned),
`SCOPE_MAX_PUBLIC_CIDR_V4`/`_V6` (16/32), `SENSOR_LATEST_VERSION` /
`SENSOR_MIN_VERSION` (set `v0.11.0` / `v0.9.0` after the sensor upgrade),
`AUDIT_RETENTION_DAYS` (365) and `AUDIT_ARCHIVE_DIR` (unset: nothing pruned),
`INGEST_VEX` (`dry_run`), `INGEST_COVERAGE_AUTO_RESOLVE` / `INGEST_SOURCE_RESOLVE`
(`dry_run`), `EASM_DNS_CHECKS_*`, `CERT_MONITOR_*`, the `SENSOR_HEARTBEAT_*` and
`SENSOR_KEY_RENEW_*` tuning values.

**Removed:** `BOOTSTRAP_ADMIN_KEY`; the `bootstrap-tenant` variables
(`TENANT_EMAIL`, `TENANT_PASSWORD`, `TENANT_TEAM_NAME`, `TENANT_TEAM_SLUG`,
`TENANT_USER_NAME`); the `openctem-admin` variables (`OPENCTEM_API_URL`,
`OPENCTEM_API_KEY`, `OPENCTEM_CONTEXT`). New for `bootstrap-admin`:
`ADMIN_BACKUP_EMAIL`, `ADMIN_BACKUP_NAME`, `ORG_NAME`, `ORG_SLUG`,
`ORG_OWNER_EMAIL`, `ORG_OWNER_NAME`.

### 3.4 Web environment variables

| Variable | Change |
|---|---|
| `NEXT_PUBLIC_SSE_BASE_URL` | Removed; use `NEXT_PUBLIC_WS_BASE_URL` (leave it empty: the WebSocket opens on the web origin and is forwarded to `BACKEND_API_URL`). |
| `NEXT_PUBLIC_API_PORT` | Removed (same reason). |
| `TRUST_PROXY_HEADERS` | New, default `false`. Set `true` only behind a proxy that **overwrites** `X-Real-IP`/`X-Forwarded-For`; pair it with `SERVER_TRUSTED_PROXIES` on the API. |
| `CSRF_SECRET` | Unchanged; at least 32 characters. Required by `api/deploy/docker-compose.yml`. |
| `NEXT_PUBLIC_TERMS_URL`, `NEXT_PUBLIC_PRIVACY_URL` | New, optional (build time). |

### 3.5 Helm (chart 0.4.1 → 0.13.0)

Use the chart whose `appVersion` is `v0.9.0`. Each chart version's upgrade notes
are in the chart README (`openctemio/helm-charts`, `charts/openctem/README.md`);
the ones that matter from 0.4.1:

| Value | Change |
|---|---|
| `api.image.repository`, `ui.image.repository` | Defaults `ghcr.io/openctemio/openctem-api` / `openctem-web` (0.4.1 named Docker Hub repositories that were never published). |
| `api.migrations.image.repository` | `ghcr.io/openctemio/migrations`; the Job runs as uid 65532. |
| `agent.*` | Mapped to `sensor.*` (deprecation notice). `agent.mode: platform`, `bootstrapToken`, `name`, `maxConcurrent`, `executors` are removed: the render fails; give `sensor.apiKey` or `sensor.existingSecret`. |
| `api.extraEnv` with `AGENT_*` | Render fails; rename to `SENSOR_*`. |
| `api.bootstrapTenant.*` | Removed; render fails while enabled. Use `api.bootstrapAdmin.org.*`. |
| `api.tenantCreationMode` | New, `admin_only`. |
| `api.bootstrapAdmin.backupEmail` / `noBackup` | A break-glass administrator is required unless `noBackup: true`. The Job is a post-install hook: it does not run on `helm upgrade`. |
| `api.attachments.*` | Attachments on a 10Gi ReadWriteOnce PVC by default (needs a default StorageClass), Deployment strategy `Recreate`. |
| `api.allowMultipleReplicas` | `api.replicaCount > 1` or autoscaling no longer renders on the default volume: use `api.attachments.storage=s3` (or ReadWriteMany). 0.4.1's `values-production.yaml` had 2 replicas. |
| `database.migrator.*` | New, optional least-privilege migrator role. |
| `gateway.*` | New, optional (`ingress`, `httpRoute` or a Caddy gateway); with a mode set, `gateway.host` and `gateway.trustedProxies` are required. |
| `sensor.*` | Sensor v0.11.0 image, state and content PVCs, hardened security context, optional local policy. |

The chart cannot run hop 1 (its migrations Job runs the v0.9.0 image, which
refuses a v0.8.0 database). Run hop 1 from a workstation as in
[4.3](#43-kubernetes), then `helm upgrade`.

### 3.6 Building images from source

The API contract files (`swagger.yaml`, `routes.txt`, `api-route-permissions.json`,
`api.types.ts`) are generated, no longer committed. A plain `docker build web`
fails without them: run `make generate` (Go and Node) or `make generate-docker`
(Docker only) at the repository root first. The API image builds without them.
`make allinone` and `make build` generate first.

---

## 4. Database migration path

### 4.1 Why two hops

v0.9.0 ships one baseline file, `001146_baseline.up.sql`, instead of the 395
migrations up to 001146 (RFC-053). golang-migrate cannot upgrade a database
whose version has no file, so a v0.8.0 database (version 224) is **refused
before anything changes**, by the migrations image, the all-in-one image and
the API's startup check:

```
This database is at migration 224, older than the migration baseline 001146.
This release creates the schema from one baseline file and cannot upgrade a
database older than it; nothing was changed. ...
```

The way through:

1. **Hop 1**: apply the migrations of git tag `pre-baseline-001146`
   (000225 → 001146). No image is published for that tag; use the upstream
   `migrate/migrate:v4.18.1` image with the tag's `api/migrations` directory.
2. **Hop 2**: apply the v0.9.0 migrations image (001147 → latest). It applies
   only the migrations above 001146; the baseline never runs on an existing
   database.

Both hops run as the database owner (the v0.8.0 `openctem` user). No
superuser and no `CREATE EXTENSION` is needed. Do not wrap them in a
transaction (`psql -1` or a runner that adds `BEGIN`): some migrations build
indexes `CONCURRENTLY`.

### 4.2 Docker Compose

With the API, web and sensors stopped and the backup taken:

```bash
# 0. Variables: the same user, password, database and sslmode as your v0.8.0
#    migrate service. NET is the Compose network the postgres service is on.
NET=<project>_app-network
DB_URL="postgres://openctem:${DB_PASSWORD}@postgres:5432/openctem?sslmode=require"

# 1. Hop 1: the migrations up to 001146 (git tag pre-baseline-001146)
mkdir -p pre-baseline && curl -fsSL \
  https://github.com/openctemio/openctem/archive/refs/tags/pre-baseline-001146.tar.gz \
  | tar -xz -C pre-baseline
docker run --rm --network "$NET" \
  -v "$PWD/pre-baseline/openctem-pre-baseline-001146/api/migrations:/migrations:ro" \
  migrate/migrate:v4.18.1 -path=/migrations -database "$DB_URL" up
#   ... 1145/u ci_db_model_validate
#   ... 1146/u remove_runner_sensors

# 2. Hop 2: the v0.9.0 migrations image
docker run --rm --network "$NET" ghcr.io/openctemio/migrations:v0.9.0 \
  -path=/migrations -database "$DB_URL" up
#   1147/u drop_down_migration_ledgers ... (the last one is the newest migration)

# 3. Check
docker compose exec postgres psql -U openctem -d openctem -c \
  "SELECT version, dirty FROM schema_migrations;"      # newest version, f
docker compose exec postgres psql -U openctem -d openctem -c \
  "SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;"   # no rows
```

With Option A ([3.2](#32-docker-compose)), hop 2 can also be the `migrate`
service of `api/docker-compose.prod.yml` (`docker compose run --rm migrate`)
once `MIGRATIONS_VERSION=v0.9.0` is set.

### 4.3 Kubernetes

Run hop 1 from a workstation that reaches the database, for example through a
port-forward (bundled PostgreSQL) or your managed database's endpoint:

```bash
kubectl -n openctem port-forward svc/<release>-postgresql 5432:5432 &
DB_URL="postgres://openctem:${DB_PASSWORD}@host.docker.internal:5432/openctem?sslmode=require"
docker run --rm --add-host=host.docker.internal:host-gateway \
  -v "$PWD/pre-baseline/openctem-pre-baseline-001146/api/migrations:/migrations:ro" \
  migrate/migrate:v4.18.1 -path=/migrations -database "$DB_URL" up
```

Then `helm upgrade` (its pre-upgrade migrations Job is hop 2). Scale the API
and web to zero before hop 1 ([10.2](#102-kubernetes--helm)).

### 4.4 How long it takes

Measured on a scratch PostgreSQL 17 (4 cores), with the commands above:

| Database | Backup (custom format) | Hop 1 | Hop 2 |
|---|---|---|---|
| Small: 21 assets, 51 findings, full v0.8.0 catalogues (93 MB with the EPSS feed) | 0.9 s (4.6 MB) | 2.3 s | 0.6 s |
| Bulk: 50,000 assets, 300,000 findings, 300,000 finding activities, 5,000 crawled URL assets (630 MB) | 6.9 s (30 MB) | 45.7 s | 49.3 s (of which 30.4 s converting the 5,000 URL assets) |

Time grows roughly with the number of assets and findings; converting crawled
URL assets costs about 6 ms each (query C4). Your rehearsal on a restored copy
([2.2](#22-backup-and-restore-test)) gives your own numbers. Several migrations
hold exclusive locks on `assets`, `findings` and the sensor tables while they
run, which is one more reason the application must be stopped.

### 4.5 If a migration fails

The migration that failed is rolled back and the version is left dirty:

```
error: migration failed ... in line N: ... (details: ...)
```

1. Read the error. The blocking cases known on v0.8.0 data are checked by
   queries B1–B4; fix the rows the query lists.
2. Set the version back to the last successful migration and clear the flag:
   `docker run ... migrate/migrate:v4.18.1 -path=/migrations -database "$DB_URL" force <previous version>`
   (each file runs in one transaction, so nothing of the failed file stayed).
3. Run the hop again. If in doubt, restore the backup and start over.

Migration `000921` deliberately refuses to run when rows reference another
organization's asset (query B1).

---

## 5. What the data migrations change

Most of the 210 migrations add tables and columns. These change existing data
in ways users or integrations notice. The "Check" column names the
[inventory query](#appendix-inventory-queries) that counts the rows.

### 5.1 Data visibility and access

| Migration | Change | Check |
|---|---|---|
| 000910 (with 000247) | **Members who are in no access group, have no explicit asset grant and no "full data access" role see no assets or findings** (lists, search, stats, exports, dashboards, reports; by-id reads answer 404). In v0.8.0 they saw the whole organization, unless it had turned on the restricted data scope setting. Owners and admins are unchanged. | C1 |
| 000372 | Being a direct asset owner no longer grants visibility; existing direct owners get an explicit grant so they keep seeing their assets. | — |
| 001044, 001051 | Data-scope rows are rebuilt from active groups and grants for active members only; suspended members' rows are dropped. | — |
| 000245 | A member's team role comes only from the four system roles. Custom roles named `owner`/`admin`/`member`/`viewer` are renamed `custom-<slug>`; custom roles above hierarchy level 79 are capped at 79. | C10 |
| 000267 | Existing active scope exclusions are kept as approved; new exclusions need approval. | — |
| 000292, 001164 | Scope wildcards: `*.example.com` now covers `example.com` too (scope targets and exclusions). Apex exclusions the upgrade would have added are removed again while their wildcard is in effect. | C13 |
| 001198, 001244 | Existing scope targets become permanent entries at tier T1 with no approval pending, origin `manual` (or `system`). | — |
| 001290 (fixed in this release) | `path` exclusions become host + path prefix (`/api/v1/*` → `*` + `/api/v1`); two legacy rows of one rule are merged into the one in effect. | C12 |
| 001303 | An SSO domain verified by two organizations is flagged `claim_conflict` (sign-in keeps working). | — |

### 5.2 Assets and the web surface

| Migration | Change | Check |
|---|---|---|
| 000684, 000685, 000773 | Asset types normalised to core type + sub-type (`website` → application/website, `ip` → ip_address, `endpoint` → host/workstation, legacy codes kept in `properties.x_native_type`). Each moved asset gets a `reclassified` history entry. Names and ids are unchanged. | — |
| 000778 | The crown-jewel flag moves from `properties.is_crown_jewel` to the `is_crown_jewel` column. | — |
| 000340, 001056 | `assets.owner_id` becomes a primary owner in `asset_owners` (owners who left the organization are dropped), then the column is dropped. | — |
| 001151 | An `ip_address` asset named like a DNS name becomes `domain`, and the reverse. | — |
| 001185 | Property synonyms are folded (`ip`, `ips`, `resolved_ip(s)`, `addresses` → `ip_addresses`; `technology` → `technologies` ...); keys only other classes may hold (a port on a domain) are removed. Previous values are kept in `asset_properties_pre_001185`. | — |
| 001288, 001317 | **Crawled URL assets (`discovered_url`) become web endpoints** (method + path template + parameter names) under their site (`http_service` asset, created when missing). Their findings and exposure events move to the site; the URL assets are deleted. v0.8.0 stored these names as `https:::host:path` (lower-cased): 001317 reads them back, the path stays lower-case until the next crawl. | C4 |
| 000294 | HTTP services stored as `https:::host` are queued for duplicate review, not renamed. | C5 |
| 001068, 001076, 001097 | Unused columns and tables dropped (`assets.freshness_status`, `compliance_requirements`, `last/next_assessment_at`, `source_id`, `source_ref`; `asset_sources`; `data_sources`). | — |

### 5.3 Scans and scan workflows

| Migration | Change | Check |
|---|---|---|
| 000230 | `agents` → `sensors` everywhere (tables, columns, permissions `agents:*` → `sensors:*`, event types `agent.*` → `sensor.*`, Tenable `execution_mode: agent` → `sensor`). | C10, C11 |
| 001285 | "Pipelines" become **scan workflows**: tables `pipeline_templates`, `pipeline_steps`, `pipeline_runs`, `step_runs` → `scan_workflows`, `scan_workflow_steps`, `scan_runs`, `scan_run_steps`; permissions `integrations:pipelines:*` → `scans:workflows:*`. Reports or BI tools that query these tables directly must be updated. | C10 |
| 001286 | `integrations:pipelines:execute` removed (a scan workflow runs only by triggering a scan). | C10, C11 |
| 001069, 001148 | Scope schedules (`scan_schedules`, never ran a scan) and scan sessions are dropped. | C14 |
| 001146 | **Runner (CI) agents are deleted** with their keys; run history keeps no sensor. | C2 |
| 001149 | The declared tool list of a sensor is dropped: dispatch uses the tools the sensor reports. | C3 |
| 001157 | Each scan's run counters and last-run fields are recomputed from its runs (numbers on the Scans page may change). | — |
| 001154 | Never-run "Quick Scan - YYYYMMDD-..." scans are marked one-off and hidden from the scan list. | — |
| 001201 | Five starter workflows are added; the old presets are deactivated (copies and scans made from them keep working). | — |
| 000241 | `gitleaks` becomes `betterleaks` in tools, scans, steps and findings. | — |

Scheduled scans that were cloned or imported have no owner and are refused at
their next scheduled run (`SCAN_HAS_NO_OWNER`): query C8; re-save each as the
member who should own it.

### 5.4 Automations

| Migration | Change | Check |
|---|---|---|
| 001212 | Automations using a trigger or action that never ran (`finding_updated`, `webhook`, `schedule`, `finding_age`; `trigger_pipeline`, `assign_team`, `update_priority`, `run_script`) are switched off; the API lists them in `unsupported_features`. The `http_request` action no longer runs. | C6 |
| — (behaviour) | An event run acts as the automation's owner (`created_by`), checked before every step; an automation with no owner runs no step until someone with the needed permissions saves or switches it on again. Automations no longer trigger each other unless `allow_automation_triggers` is set; at most 200 runs per automation and 5,000 per organization per hour. | C7 |

### 5.5 Findings, severity and SLA

| Migration | Change | Check |
|---|---|---|
| 000640 | Branch findings closed as `resolved/branch_expired` become `not_observed` (open, SLA keeps running). A CHECK constraint on `findings.status` is added. | B2 |
| 000751 | Findings closed by a suppression rule become `false_positive` or `accepted` instead of `resolved` (fix rate and MTTR count real fixes only). | — |
| 000300, 000301 | Secret-scanner findings become `finding_type = secret`; CVE ids are normalised and linked. | — |
| 000941, 000942 | SLA priority windows that were never read are cleared; escalation is switched on; priority override rules with invalid conditions are disabled. | — |
| 001138 | Findings seen only on a non-default, non-protected branch are flagged `branch_only` and left out of dashboards, SLA and metrics. | — |
| 001180 | **Informational findings get no SLA by default**: policies on the shipped 90/365-day info window move to 0 and open info findings lose their deadline. Set the info window again if you want one. | C9 |
| 001012 | Finding history entries that named an assignee outside the organization show "Former assignee (not in this organization)". | — |
| 001018 | Duplicate open Certificate Transparency exposures are resolved. | — |

Retest outcomes are renamed (`fixed` → `not_reproduced`, `still_present` →
`still_vulnerable`, `unknown` → `inconclusive`, migration 001242), and a
"not reproduced" retest no longer closes a finding by itself: a confirmed fix
moves it to "Verified fixed — awaiting confirmation". Coming from v0.8.0 there
are no rows to rename (the retest table is created by the upgrade); pentest
campaign retests are unchanged.

### 5.6 Other

| Migration | Change | Check |
|---|---|---|
| 000227 | Platform administrator API keys are revoked and every v0.8.0 administrator row is deactivated. | C15 |
| 000673, 000670 | Permission sets and group-level permissions are removed (permissions come from roles only). | C10 |
| 001052 | `tenants.settings.api` (including a plain-text webhook secret) is removed. | — |
| 001059, 001075, 001079, 001092, 001147 | Unused objects dropped: the `deprecated` schema, `webhook_deliveries`, `webhooks` (outbound webhooks never delivered), seeded platform settings, rule-management tables, two down-migration ledgers. | B4, C14 |
| 001057 | 117 redundant indexes dropped. | — |

---

## 6. API and integration changes

There are **no aliases**: an old path answers 404 (or 405). Update every
script, integration and API client before you turn them back on.

### 6.1 Removed or renamed routes

| v0.8.0 | v0.9.0 |
|---|---|
| `/api/v1/agent/*` (sensor protocol v1) | `/api/v2/sensor/*` (sensors v0.9.0 and later); `ingest/sarif`, `ingest/recon`, `ingest/scan`, `scans`, `telemetry-events`, `credentials/ingest` have no successor |
| `/api/v1/agents[/{id}...]` | `/api/v1/sensors[/{id}...]` (the 308 redirect is gone) |
| `/api/v1/pipelines[/{id}...]` (steps, activate, clone) | `/api/v1/scan-workflows[/{id}...]` |
| `POST /api/v1/pipelines/{id}/runs` | removed: trigger a scan (`POST /api/v1/scans/{id}/trigger`) |
| `GET /api/v1/pipelines/{id}/runs` | `GET /api/v1/scan-runs?scan_workflow_id=` |
| `/api/v1/pipeline-runs[/{id}[/cancel]]` | `/api/v1/scan-runs[/{id}[/cancel]]` (also `/tasks`, `/stages`, `/tasks/{task_id}/logs`) |
| `/api/v1/scan-sessions[...]` | removed: `GET /api/v1/scans/{id}/runs`, `GET /api/v1/scan-runs` |
| `/api/v1/scope/schedules[...]` | removed: create a scheduled scan |
| `GET /api/v1/tools/platform`, `/tools/name/{name}` | `GET /api/v1/tools?source=platform`, `GET /api/v1/tools?q={name}` |
| `POST /api/v1/tools/{id}/activate`, `/deactivate`; `/custom-tools/{id}/activate`, `/deactivate` | `PATCH /api/v1/tools/{id}/settings {"is_enabled": ...}` |
| `/api/v1/custom-tools[/{id}]` | `/api/v1/tools[/{id}]` (`?source=custom`) |
| `/api/v1/tenant-tools[/{toolId}]`, `/effective-config`, `/with-config`, `/all-tools`, `/availability`, `/stats` | `GET /api/v1/tools[/{id}]?include=settings,availability,stats`; `PUT` → `PATCH /api/v1/tools/{id}/settings` |
| `POST /api/v1/tenant-tools/bulk/enable`, `/disable` | `PATCH /api/v1/tools/settings {"tool_ids": [...], "is_enabled": ...}` |
| `/api/v1/custom-tool-categories[/{id}]`, `GET /tool-categories/all` | `/api/v1/tool-categories[/{id}]`, `?per_page=100` |
| `GET /api/v1/capabilities/all`, `/by-category/{c}`, `/{id}/usage-stats`; `POST /capabilities/usage-stats`; `/custom-capabilities[/{id}]` | `GET /api/v1/capabilities?per_page=100`, `?category=`, `?include=usage`; `POST/PUT/DELETE /api/v1/capabilities[/{id}]` |
| `GET /api/v1/platform/stats` | `GET /api/v1/platform/scanning` |
| `GET /api/v1/dashboard/stats/global` | `GET /api/v1/dashboard/stats` (current organization) |
| `POST /api/v1/audit-logs/rebaseline` | platform administrator only (admin console) |
| `POST /api/v1/assets/import/nessus`, `/import/nessus-findings` | `POST /api/v1/findings/import` (multipart part `file`) |
| `POST /api/v1/assets/import/kubernetes`, `POST /api/v1/integrations/{id}/import-repositories`, `GET /api/v1/findings/analytics/sources`, `PATCH /api/v1/tenants/{t}/settings/branch` | removed |
| `POST/DELETE /api/v1/findings/{id}/link-ticket` | `POST /api/v1/findings/{id}/create-ticket` |
| `POST /api/v1/findings/{id}/request-verification` | mark `fix_applied` (starts a proof-of-fix retest) or `POST /api/v1/findings/{id}/retests` |
| `GET /api/v1/asset-types/categories[/{id}]` | `GET /api/v1/asset-types` |
| `GET/PUT /api/v1/tenants/{t}/settings/asset-source`, `PATCH .../settings/api`, `GET/PATCH .../settings/data-scope` | removed |
| `DELETE /api/v1/tenants/{t}/members/{id}` | `POST /api/v1/organization/members/{id}/offboard` (step-up; a reassignment plan when the member owns work) |
| `/api/v1/settings/saml`, `/settings/identity-providers`, `/settings/verified-domains` | platform admin console: `/api/v1/admin/tenants/{tenantId}/sso/...`; ownership proof for scanning: `/api/v1/easm/verified-domains` |
| `/api/v1/permission-sets[...]`, `/api/v1/groups/{id}/permission-sets` | removed (permissions come from roles) |
| `/api/v1/webhooks[...]` (outbound) | removed; inbound `/api/v1/webhooks/incoming/*` unchanged |
| `GET /api/v1/auth/ws-token` | removed; `/api/v1/ws` uses the session cookie or a Bearer token |
| `POST /api/v1/vulnerabilities`, `PUT/DELETE /api/v1/vulnerabilities/{id}`, `POST /api/v1/threat-intel/sync`, `PATCH /threat-intel/sync/{source}` | 405 (catalogue feeds are managed by the platform administrator) |
| `POST /api/v1/admin/users`, `/admin/users/{id}/rotate-key` | admin console (`POST /api/v1/admin/administrators`); no admin API keys |
| `POST /api/v1/auth/token` with `AUTH_PROVIDER=oidc` | removed (the identity provider issues tokens) |

### 6.2 Same path, different contract

| Route(s) | Change |
|---|---|
| Scans, scan runs, previews | JSON `pipeline_id` → `scan_workflow_id`, `pipeline_run_id` → `scan_run_id`, `step_run_id` → `scan_run_step_id`, `pipeline_name` → `scan_workflow_name`; scan stats `pipelines` → `scan_runs`. |
| `GET /scans`, `/scans/{id}/runs`, `/scan-runs`, `/scan-workflows` | One envelope `{data, total, page, per_page, total_pages}` (`items` → `data`); a non-numeric `page`/`per_page` is 400; `per_page` at most 100. |
| `POST /api/v1/assets` | An asset that already exists is **409** (it used to merge). Update the named asset, or send data through ingest. |
| `POST /api/v1/scope/check` | New body `{"targets": [...], "sensor_preference", "tier"}`; the old `{"asset_type", "value"}` is gone. |
| Scope entries and exclusions | `created_by`, `approvals[].approver`, `rejected_by`, `approved_by` are objects (`created_by.id`); new `origin`. Creating or widening a scope target needs `attack_surface:scope:approve` and step-up, and may wait for a second administrator (202, pending). Members request one-off entries. |
| `PATCH /findings/{id}/status`, `POST /findings/bulk/status`, remediation-group resolve | Moving to `resolved` needs `findings:verify` (403 otherwise). |
| `POST /api/v1/sensors`, `PUT /api/v1/sensors/{id}` | `tools` removed; new organizations need sensor pairing (`403 BEARER_KEYS_DISABLED`); creating a key needs step-up. |
| `POST /api/v1/workflows/{id}/runs` (automations) | Acts as the caller; names its subject with `finding_id` or `asset_id`; `trigger_data` and non-manual triggers are refused. |
| Scan trigger errors | Codes `NO_SENSOR_FOR_TOOL`, `NO_SENSOR_AVAILABLE`, `TOOL_NOT_FOUND`, `TOOL_DISABLED`, `TOOL_NOT_SCANNER`, `TARGET_OUT_OF_SCOPE` (with `details.refused[]`), `WILDCARD_TARGET`, `SCAN_FREEZE_ACTIVE` instead of `BAD_REQUEST`; a refused trigger is recorded as a `blocked` run. |
| `GET /findings/stats` | Severity key `none` → `info`. |
| `POST /auth/create-first-team`, `POST /tenants` | 403 with `TENANT_CREATION_MODE=admin_only`. |
| `POST /auth/register` | 403 unless registration is on or the person is invited. |
| `POST /findings/ai-triage/bulk` | Deprecated (`Sunset: 2027-01-15`). |

### 6.3 API keys (`oct_`) and step-up

- `oct_` keys now work on the REST API, **read-only** (GET, HEAD, OPTIONS);
  any write answers 403. A key's scopes are narrowed to what its owner holds
  now; a key never gets admin rights or full data access; the organization's
  IP allowlist applies. New keys need `expires_in_days` (1–365).
- Scopes are renamed with the permissions (`agents:*` → `sensors:*`,
  `integrations:pipelines:*` → `scans:workflows:*`); `integrations:pipelines:execute`
  is stripped. Scripts that **create** keys or roles must send the new names.
- **Step-up:** these actions answer `403 STEP_UP_REQUIRED` unless the session
  signed in or called `POST /api/v1/auth/step-up` (password, or the 2FA code
  when 2FA is on) within 10 minutes: creating and deleting API keys, creating a
  SCIM token, organization security settings, approving an SSO change,
  deleting the organization, resetting a member's 2FA, offboarding or erasing a
  member, CI gate break-glass, creating a sensor or regenerating its key,
  revealing a leaked credential or finding evidence, reading or rotating the
  Jira/GitHub webhook secrets, the attachment storage configuration, scope
  settings, approving scope entries, lifting or narrowing scope exclusions,
  granting the admin or owner role, changing the organization slug, widening a
  sensor grant. API keys and external OIDC tokens get `403 STEP_UP_UNAVAILABLE`
  there. The web console asks and retries by itself.

### 6.4 Web console URLs

Pages that moved **without a redirect** (update bookmarks and links in tickets):

| v0.8.0 | v0.9.0 |
|---|---|
| `/agents` | `/sensors` |
| `/pipelines`, `/pipelines/{id}/builder` | `/scans/workflows`, `/scans/workflows/{id}` |
| `/workflows` | `/automations` |
| `/scans?tab=runs` | `/scans/runs` |
| `/scope-config` | `/scope` |
| `/asset-groups[/{id}]` | `/assets/groups[/{id}]` |
| `/relationships/suggestions` | `/assets/suggestions` |
| `/settings/integrations/verified-domains` | `/scope?tab=proof` |

Most settings pages moved with a permanent redirect (for example
`/settings/users` → `/settings/members`, `/tools` → `/settings/scanning/tools`,
`/pentest/retests` → `/validation/retests`, `/runners` → `/ci-cd`). Per-organization
SSO set-up moved to the platform admin console.

---

## 7. Permissions and roles

System roles are updated by the migrations; **custom roles are converted
automatically** for renames, but review them for removals and for the new
behaviour.

**Renamed** (role grants, custom roles, API key scopes):

| v0.8.0 | v0.9.0 |
|---|---|
| `agents:read`, `agents:write`, `agents:delete`, `agents:commands:read`, `agents:commands:write`, `agents:commands:delete` | `sensors:read`, `sensors:write`, `sensors:delete`, `sensors:commands:read`, `sensors:commands:write`, `sensors:commands:delete` |
| `integrations:pipelines:read`, `:write`, `:delete` | `scans:workflows:read`, `:write`, `:delete` |

**Removed:** `integrations:pipelines:execute`, `scans:tenant_tools:delete`,
`findings:vulnerabilities:write`, `findings:vulnerabilities:delete`,
`integrations:webhooks:read|write|delete`, `team:permission_sets:read|write|delete`,
`compliance:frameworks:write`, `compliance:reports:read`,
`findings:policies:read|write|delete`, `settings:billing:read|write`.
Removed rows are archived in `access_control_removed_archive`.

**Admin-only** (refused on custom roles, and stripped from existing custom roles
by migration 000945): `sensors:write`, `sensors:delete`, `sensors:commands:delete`,
`sensors:zones:write`, `sensors:zones:delete`, `sensors:pair`, `sensors:approve`,
`sensors:grant:narrow`, `sensors:grant:widen`, `sensors:revoke`, `scans:ci:write`,
`scans:ci:override`. A custom "sensor operator" role that could create agents in
v0.8.0 can no longer create sensors.

**Added** (owner and admin unless noted): `attack_surface:scope:approve`,
`attack_surface:scope:exclusions:approve`, `findings:credentials:reveal`,
`findings:evidence:reveal` (assignable to custom roles), `scans:freeze:override`,
`scans:ci:read` (every system role), `scans:ci:write`, `scans:ci:override`,
`sensors:zones:read` (every system role), `sensors:zones:write|delete`,
`sensors:pair`, `sensors:approve`, `sensors:grant:narrow`, `sensors:grant:widen`,
`sensors:revoke`, `dashboard:aggregate`.

**System role changes:** Member and Viewer lose `audit:read` and
`settings:billing:read`; Member loses `scans:templates:write` and
`scans:sources:write` and gains `assets:import` and `findings:exposures:triage`.
Migration 000771 grants companion permissions to every role that held the gate
permission (`scans:write` → `scans:execute`, `findings:read` →
`ai_triage:read` + `findings:exposures:read`, ...), and `team:read`,
`team:members:read`, `settings:read` to every custom role, so nobody loses
access by it.

**Behaviour tied to permissions** that custom roles may need:

- resolving a finding needs `findings:verify` (members keep `fix_applied`);
- custom tools and categories, and tool configuration overrides, need
  `scans:tools:write` / `scans:tools:delete` (members keep the on/off switch);
- a permanent scope target needs `attack_surface:scope:approve`;
- a member with no data scope row sees nothing, whatever the role (a custom role
  with "full data access" sees everything).

---

## 8. Sensors and CI

### 8.1 Compatibility

| | API v0.8.0 | API v0.9.0 |
|---|---|---|
| agent v0.2.x (v0.8.0 era), sensor ≤ v0.8.x | works (protocol v1) | **does not work**: `/api/v1/agent/*` answers 404 |
| sensor v0.9.0, v0.9.1 | works (falls back to protocol v1) | works (protocol v2) |
| sensor v0.10.0, **v0.11.0** | does not work (protocol v2 only; v0.8.0 serves none) | **works**: target version |
| `ghcr.io/openctemio/sensor:*-ci`, runner agents | works | **does not work**: CI moved to `openctemio/ci` with OIDC |

Verified on the scratch upgrade with a sensor key created in v0.8.0
(`rda_...`): sensor v0.9.1 works against the v0.8.0 API (protocol 1) and
against the upgraded API (protocol 2); sensor v0.11.0 works against the
upgraded API; the same key on `/api/v1/agent/heartbeat` of the upgraded API
gets 404.

### 8.2 Upgrade order

Recommended: move the sensors to the bridge version first, so nothing about
them has to happen inside the window.

1. **Before the window:** upgrade every sensor to **v0.9.1**
   (`ghcr.io/openctemio/sensor:v0.9.1`). It keeps working with v0.8.0 and works
   with v0.9.0. Check each is *online* again. (If you skip this step, stop the
   v0.8.0-era agents with the platform: they cannot reach the new API, and
   commands in flight are lost, query C20.)
2. **In the window:** upgrade the API and web ([10](#10-upgrade-procedure)).
   The v0.9.1 sensors reconnect on their own when the API is back.
3. **After the window:** upgrade every sensor to **v0.11.0**: image `ghcr.io/openctemio/sensor:v0.11.0`
   (binary `openctemio-sensor`). `API_URL` and `API_KEY` are unchanged; the
   existing key keeps working. `AGENT_ID`, `AGENT_NAME`,
   `AGENT_ALLOW_PRIVATE_TARGETS` still work with a deprecation warning: rename
   them to `SENSOR_*`. Remove `SENSOR_PROTOCOL=v1`/`-protocol v1` if set (refused
   at start-up). Pin the image by version or digest, not `latest`.
4. The default image no longer carries semgrep, betterleaks or trivy; a daemon
   that runs them uses the per-tool images `sensor:v0.11.0-semgrep`, `-trivy`,
   `-betterleaks`.
5. Set `SENSOR_LATEST_VERSION=v0.11.0` and, once every sensor is upgraded,
   `SENSOR_MIN_VERSION=v0.9.0` on the API.

### 8.3 After the upgrade: grants, trust and templates

- Every existing sensor gets the **legacy broad grant** at trust level
  *Trusted* (migration 001119): it keeps doing what it did. The Sensors page
  flags it; narrow it per sensor (Sensors → sensor → Grant). Widening needs
  `sensors:grant:widen` and step-up.
- A sensor created after the upgrade starts at trust level *New* (passive jobs
  only, no push ingest) until an administrator promotes it. Existing
  organizations keep API-key sensors allowed (`sensor_bearer_keys_allowed`);
  pairing (`openctemio-sensor pair <CODE>`) is the recommended way for new ones.
- A sensor gets only the tools it reports (the declared tool list is gone).
- Custom nuclei templates reach sensors only in a signed manifest: pin the
  organization's public key on each sensor (`GET /api/v1/scanner-templates/signing-key`
  → `SENSOR_TEMPLATE_SIGNING_KEYS`), or sensors refuse custom templates. Scans
  without custom templates are unaffected.
- Scans with zones: a private address is scanned only by a sensor in a scan
  zone that holds it. Platform (shared) sensors are not visible to
  organizations and cannot be pinned.

### 8.4 CI pipelines

The runner agent type is deleted by the upgrade (query C2), and CI scanning is
no longer part of the sensor. CI jobs authenticate with their CI provider's
OIDC token instead of a stored key:

1. In OpenCTEM: Settings → Scanning → CI/CD integration → add a trust
   configuration for your GitHub organization, GitLab group, Azure DevOps
   organization, Bitbucket workspace, CircleCI organization or Jenkins
   controller.
2. In the pipeline: use `openctemio/ci` (`uses: openctemio/ci@v1` on GitHub,
   or its GitLab templates) with `OPENCTEM_TENANT_ID`, and delete the
   `API_KEY` secret.
3. When every pipeline uses OIDC, turn on "Require OIDC for CI".

How-tos: [Connect CI pipelines](../how-to/connect-ci-pipelines.md),
[GitLab CI](../how-to/gitlab-ci.md).

---

## 9. Sign-in, SSO and identity provider changes

### 9.1 Platform administrators

v0.8.0 administrators were `admin_users` rows with API keys. In v0.9.0 an
administrator is a sign-in account in no organization, linked to an
`admin_users` row, who signs in on `/login` and opens the console with a TOTP
code. Migration 000227 **revokes every admin API key and deactivates every
v0.8.0 administrator**. After the upgrade:

```bash
# new primary administrator + break-glass backup (emails with no account yet)
docker run --rm --network "$NET" -e DATABASE_URL="$DB_URL" ghcr.io/openctemio/admin-cli:v0.9.0 \
  -email=secops-admin@example.com -backup-email=breakglass@example.com
# or keep a v0.8.0 administrator's email and role
docker run --rm --network "$NET" -e DATABASE_URL="$DB_URL" ghcr.io/openctemio/admin-cli:v0.9.0 \
  -email=<old admin email> -link
```

Each prints a temporary password once. Sign in, change it, enroll the
authenticator. Store the break-glass credentials offline.

### 9.2 Identity provider changes (do these before the window)

| Provider | Change | Action at the provider |
|---|---|---|
| Microsoft Entra ID | Step-up for SSO users needs the signed authentication time | App registration → Token configuration → Add optional claim → ID → **`auth_time`**. Keep **`xms_edov`** (already required in v0.8.0). |
| Google Workspace | The `hd` (hosted domain) claim is checked | A provider without allowed domains needs the Workspace primary domain verified for the organization; consumer Google accounts are refused. |
| Any OIDC/SAML | "Sign in again" in the step-up dialog forces re-authentication (`prompt=login`, `max_age=0`; SAML `ForceAuthn`) | The IdP must support forced re-authentication. |
| Keycloak (`AUTH_PROVIDER=oidc`/`hybrid`) | Tokens verified by the shared verifier: RSA keys ≥ 2048 bits, tokens ≤ 32 KiB, 30 s clock skew | `KEYCLOAK_BASE_URL` and `KEYCLOAK_REALM` must form the issuer. |

### 9.3 Behaviour changes users notice

- SSO, SAML, identity-provider and verified-domain settings move to the
  platform admin console (existing configurations are kept). Only the platform
  administrator changes them.
- SSO just-in-time provisioning needs the email domain **DNS-verified** for the
  organization and in the allowed domains (query C19); the default JIT role is
  `viewer`.
- An SSO domain can be verified by one organization only (query: rows with
  `claim_conflict` after the upgrade).
- "Require two-factor authentication" is enforced: local-password members
  enroll TOTP at their next sign-in (query C18). SSO sign-ins are exempt.
- The IP allowlist is enforced on every request (query C16): the API must see
  the real client IP (`SERVER_TRUSTED_PROXIES` on the API, `TRUST_PROXY_HEADERS`
  on the web behind a proxy that overwrites the headers), or everyone in that
  organization gets `403 IP_NOT_ALLOWED`. Clear the list before the upgrade if
  you cannot set this up.
- Allowed email domains are enforced for invitations, new users, SCIM and JIT
  (query C17).
- Sessions are revoked immediately on sign-out, password change and suspension.
- Removing a member offboards them (keys revoked, work reassigned); nobody is
  hard-deleted.

---

## 10. Upgrade procedure

### 10.1 Docker Compose

Assumes Option A ([3.2](#32-docker-compose)), the API project in `api/` and
the web project in `web/` of a `v0.9.0` checkout, and your env files updated as
in [3.3](#33-api-environment-variables) and [3.4](#34-web-environment-variables).

```bash
API="docker compose -p <api project> -f docker-compose.yml -f docker-compose.prod.yml"   # in api/
WEB="docker compose -p <web project> -f docker-compose.prod.yml"                         # in web/

# 1. Before the window: pull the images (no downtime)
#    API_VERSION=v0.9.0 MIGRATIONS_VERSION=v0.9.0 UI_VERSION=v0.9.0
#    API_IMAGE=ghcr.io/openctemio/openctem-api UI_IMAGE=ghcr.io/openctemio/openctem-web
$API pull migrate app && $WEB pull

# 2. Stop web and API (keep postgres and redis; v0.9.1 sensors may keep running)
$WEB stop
$API stop app

# 3. Backup (2.2) and inventory (2.5) of the final state
# 4. Hop 1 and hop 2 (4.2)
# 5. Check the sensor vocabulary conversion
$API run --rm --no-deps app -sensor-upgrade-check   # every line ok/kept

# 6. Flush the permission cache (permissions were renamed)
$API exec redis sh -c 'redis-cli --no-auth-warning -a "$0" --scan --pattern "user_perms:*" \
  | xargs -r redis-cli --no-auth-warning -a "$0" DEL' "$REDIS_PASSWORD"

# 7. Start the API, then the web
$API up -d app        # the one-shot migrate service runs first: a no-op now
$API ps app           # healthy
$API logs --since 10m app | grep '"level":"ERROR"'   # nothing
$WEB up -d

# 8. Platform administrators (9.1), then sensors (8.2), then verification (11)
```

### 10.2 Kubernetes / Helm

1. Prepare the values from [3.5](#35-helm-chart-041--0130) and check them with `helm template`.
2. Back up; scale the API, web and bundled sensor to zero (keep PostgreSQL
   and Redis running if they are in the release):
   ```bash
   for c in api ui agent; do
     kubectl -n $NS scale deploy -l app.kubernetes.io/instance=$REL,app.kubernetes.io/component=$c --replicas=0
   done
   ```
3. Hop 1 from a workstation ([4.3](#43-kubernetes)).
4. `helm upgrade $REL openctemio/openctem --version <chart with appVersion v0.9.0> -n $NS -f values.yaml --wait --timeout 20m`
   (the pre-upgrade migrations Job is hop 2; `kubectl -n $NS logs -f job/<fullname>-api-migrations`).
5. `kubectl -n $NS exec deploy/<fullname>-api -- ./server -sensor-upgrade-check`,
   then flush `user_perms:*` in Redis as in 10.1.
6. Create the administrators: `kubectl -n $NS exec deploy/<fullname>-api -- ./bootstrap-admin -email=... -backup-email=...`
   (the chart's bootstrap Job does not run on upgrade).
7. Sensors ([8.2](#82-upgrade-order)) and verification.

---

## 11. Post-upgrade verification

Run as an owner, a member and a viewer of one organization:

- [ ] `SELECT version, dirty FROM schema_migrations;` → the newest version, `f`;
      `SELECT count(*) FROM pg_index WHERE NOT indisvalid;` → 0.
- [ ] `GET /health` → `healthy`; `GET /ready` → database and Redis `ok`.
- [ ] `./server -sensor-upgrade-check` → "Upgrade complete".
- [ ] No `ERROR` in the API log since start.
- [ ] Each person signs in and sees the same assets, findings and scans as
      before (members: only after they are in an access group).
- [ ] Re-run the inventory counts and compare with `inventory-before.txt`:
      users, findings and scans unchanged; assets = before − URL assets (C4) +
      sites created for them; scope targets unchanged; scope exclusions =
      before − merged path duplicates (C12); sensors = before − runner agents (C2).
- [ ] Web surface (Assets → Web surface) lists the converted URLs.
- [ ] Each upgraded sensor is *online* with protocol 2, and a small scan
      completes.
- [ ] Administrators sign in on `/login` and reach `/admin` after the TOTP step.
- [ ] `POST /api/v1/auth/register` → 403 (unless kept open);
      `POST /api/v1/tenants` as an owner → 403 (unless `self_service`).
- [ ] A step-up action (create an API key) asks for the password and works.
- [ ] Organizations with an IP allowlist: an owner is not refused, and
      Settings → Security shows their real IP.
- [ ] HTTP services still named `https:::host` (query C5): rename each to its URL
      (`https://host`) on the asset page, or new crawls create a second asset
      for the same site.
- [ ] Automations listed by C6/C7: replace the unsupported step or save them
      again as their owner.

---

## 12. Rollback

**Restore the pre-upgrade backup.** It is the only exact way back:

```bash
$WEB stop; $API stop app
docker compose exec postgres dropdb -U openctem openctem
docker compose exec postgres createdb -U openctem openctem
docker compose exec -T postgres pg_restore -U openctem -d openctem --no-owner < openctem-v0.8.0-<stamp>.dump
# back to the v0.8.0 images, env files and the old sensors, then start
```

There is no supported down path to v0.8.0: the baseline's down migration
refuses (it never drops the schema), and many migrations cannot be reversed:

- discovered-URL assets converted to web endpoints (001288, 001317);
- runner agents deleted (001146), declared sensor tool lists (001149);
- revoked admin API keys and deactivated administrators (000227);
- the data-scope policy (000910), scope rows rebuilt (001051), deleted
  cross-tenant group links (000352, 000455);
- custom role slugs renamed and levels capped (000245);
- finding statuses moved (000640, 000751), cleared info SLA deadlines (001180),
  the scrubbed assignee names (001012);
- dropped tables and columns: webhooks, scope schedules, scan sessions,
  `assets.owner_id` (owners who had left), permission sets, the `deprecated`
  schema, `tenants.settings.api`;
- merged duplicate path exclusions (001290).

Data written after the upgrade (new findings, scans, users) is lost by a
restore; decide within the window. Sensors upgraded to v0.10 or later must be
set back to their v0.8.0-era version to talk to a restored v0.8.0 API.

---

## 13. What's new for your users

Short version for an announcement:

- **Scoping you can trust:** one Scope page (In scope, Out of scope,
  Approvals). `*.example.com` covers `example.com`; widening scope needs a
  second administrator; one-off entries expire; path exclusions with a
  read-only testing mode. Every scan refusal says why and how to fix it.
- **Scans:** Scans, Runs and Workflows tabs; starter workflows (Discover,
  Discover + Vuln, Web app, Network, Code / CI); workflow steps pick tools by
  capability and spread over every eligible sensor; preview before you run;
  freeze windows; per-task logs.
- **Web surface:** crawled URLs are endpoints under their site, with
  parameters, change feed and sensitive-path flags; upload OpenAPI, Postman,
  HAR or GraphQL descriptions to see shadow and zombie endpoints.
- **Findings:** tool evidence (request, response, reproduction) with secrets
  masked; import files from other scanners (Nessus, SARIF, trivy, grype,
  semgrep, ZAP, CycloneDX, SPDX, OSV, CSAF, OpenVEX, ...); honest retests
  ("Verified fixed — awaiting confirmation"); a `not_observed` status;
  informational findings without SLA.
- **CI/CD:** CI pipelines report with their provider's OIDC identity and a
  central gate; coverage per repository.
- **Sensors:** pairing without handling keys, per-sensor grants and trust
  levels, tool availability per sensor.
- **Security:** step-up re-authentication for sensitive actions, member
  offboarding with reassignment, data scope by teams, 2FA for everyone.

---

## Appendix: inventory queries

Read-only, checked against the v0.8.0 schema (migration 224). Save as
`v0.9-inventory.sql`. Queries B1–B4 must return zero rows (or only zero
counts); the others tell you what changes.

<details markdown="1">
<summary><code>v0.9-inventory.sql</code></summary>

```sql
-- OpenCTEM v0.8.0 -> v0.9.0 inventory. Read-only. Run on the v0.8.0 database.

-- P0. Versions and size
SHOW server_version;
SELECT version, dirty FROM schema_migrations;
SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;
SELECT (SELECT count(*) FROM users) AS users, (SELECT count(*) FROM assets) AS assets,
       (SELECT count(*) FROM findings) AS findings, (SELECT count(*) FROM scans) AS scans,
       (SELECT count(*) FROM scope_targets) AS scope_targets, (SELECT count(*) FROM scope_exclusions) AS scope_exclusions,
       (SELECT count(*) FROM agents) AS agents, (SELECT count(*) FROM workflows) AS automations;

-- B1. Migration 000921 refuses to run while rows point at another organization's asset. Must be all 0.
SELECT 'findings' AS ref, count(*) FROM findings x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'exposures', count(*) FROM exposures x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'exposure_events', count(*) FROM exposure_events x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'asset_relationships', count(*) FROM asset_relationships x JOIN assets a ON a.id IN (x.source_asset_id, x.target_asset_id) WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'asset_services', count(*) FROM asset_services x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'asset_components', count(*) FROM asset_components x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'asset_state_history', count(*) FROM asset_state_history x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'assets.parent_id', count(*) FROM assets x JOIN assets a ON a.id = x.parent_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'business_unit_assets', count(*) FROM business_unit_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'business_service_assets', count(*) FROM business_service_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'pipeline_runs', count(*) FROM pipeline_runs x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'scan_sessions', count(*) FROM scan_sessions x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'sla_policies', count(*) FROM sla_policies x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'suppression_rules', count(*) FROM suppression_rules x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'relationship_suggestions', count(*) FROM relationship_suggestions x JOIN assets a ON a.id IN (x.source_asset_id, x.target_asset_id) WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'scan_coverage_state', count(*) FROM scan_coverage_state x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'runtime_telemetry_events', count(*) FROM runtime_telemetry_events x JOIN assets a ON a.id = x.endpoint_asset_id WHERE x.tenant_id <> a.tenant_id
UNION ALL SELECT 'user_accessible_assets', count(*) FROM user_accessible_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id;

-- B2. Migration 000640 adds a CHECK on findings.status. Must be empty: map these statuses to a listed one first.
SELECT status, count(*) FROM findings
 WHERE status NOT IN ('new','open','confirmed','in_progress','fix_applied','validated_fixed','not_observed','resolved',
                      'false_positive','accepted','duplicate','draft','in_review','remediation','retest','verified','accepted_risk')
 GROUP BY status;

-- B3. Migration 000825 needs a CVE id on every catalogue row. Must be empty.
SELECT id, cve_id FROM vulnerabilities WHERE cve_id IS NULL OR btrim(cve_id) = '';

-- B4. Migration 001059 drops the "deprecated" schema and only the objects it knows. Must be empty.
SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'deprecated' AND c.relkind IN ('r','v','m','f','p')
   AND c.relname NOT IN ('agent_audit_logs','agent_metrics','email_logs','finding_regression_events',
                         'registration_tokens','scan_profile_template_sources','threat_actor_cves');

-- C1. Members who will see no assets or findings (not owner/admin, in no access group)
SELECT t.slug, count(*) AS members_without_a_team
  FROM tenant_members tm JOIN tenants t ON t.id = tm.tenant_id
 WHERE tm.role NOT IN ('owner','admin')
   AND NOT EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON g.id = gm.group_id
                    WHERE gm.user_id = tm.user_id AND g.tenant_id = tm.tenant_id)
 GROUP BY t.slug;

-- C2. CI runner agents that the upgrade deletes (001146)
SELECT t.slug, a.name, a.execution_mode, a.last_seen_at
  FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE a.type = 'runner';

-- C3. Agents, their declared tools (dropped by 001149) and last heartbeat
SELECT t.slug, a.name, a.type, a.version, a.last_seen_at, a.tools
  FROM agents a JOIN tenants t ON t.id = a.tenant_id ORDER BY 1, 2;

-- C4. Crawled URL assets that become web endpoints (001288/001317), and their findings
SELECT count(*) AS url_assets,
       (SELECT count(*) FROM findings f JOIN assets u ON u.id = f.asset_id
         WHERE u.asset_type = 'discovered_url' OR u.sub_type = 'discovered_url') AS findings_moved_to_their_site
  FROM assets WHERE asset_type = 'discovered_url' OR sub_type = 'discovered_url';

-- C5. HTTP services stored under a broken name ("https:::host"): rename after the upgrade
SELECT t.slug, a.name FROM assets a JOIN tenants t ON t.id = a.tenant_id
 WHERE a.asset_type = 'service' AND a.sub_type = 'http' AND a.name ~ '^https?:::' ORDER BY 1, 2;

-- C6. Automations switched off by 001212 (or whose http_request step stops running)
SELECT t.slug, w.name FROM workflows w JOIN tenants t ON t.id = w.tenant_id
 WHERE w.is_active AND EXISTS (SELECT 1 FROM workflow_nodes n WHERE n.workflow_id = w.id
   AND (n.config->>'trigger_type' IN ('finding_updated','webhook','schedule','finding_age')
        OR n.config->>'action_type' IN ('trigger_pipeline','assign_team','update_priority','run_script','http_request')));

-- C7. Automations without an owner (run no step until saved again)
SELECT t.slug, w.name FROM workflows w JOIN tenants t ON t.id = w.tenant_id WHERE w.is_active AND w.created_by IS NULL;

-- C8. Scheduled scans without an owner (refused at their next scheduled run)
SELECT t.slug, s.name FROM scans s JOIN tenants t ON t.id = s.tenant_id
 WHERE s.created_by IS NULL AND s.schedule_type <> 'manual' AND s.status = 'active';

-- C9. SLA policies on a shipped info window (set to 0 = no SLA), open info findings that lose their deadline
SELECT t.slug, p.name, p.info_days FROM sla_policies p JOIN tenants t ON t.id = p.tenant_id WHERE p.info_days IN (90, 365);
SELECT count(*) AS open_info_findings_with_deadline FROM findings
 WHERE severity IN ('info','none') AND sla_deadline IS NOT NULL
   AND status NOT IN ('resolved','false_positive','accepted','duplicate','verified','accepted_risk');

-- C10. Custom-role permissions that are renamed, removed or become admin-only
SELECT t.slug, r.name AS role, rp.permission_id FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id JOIN tenants t ON t.id = r.tenant_id
 WHERE rp.permission_id LIKE 'agents:%' OR rp.permission_id LIKE 'integrations:pipelines:%'
    OR rp.permission_id LIKE 'integrations:webhooks:%' OR rp.permission_id LIKE 'team:permission_sets:%'
    OR rp.permission_id IN ('scans:tenant_tools:delete','findings:vulnerabilities:write','findings:vulnerabilities:delete',
                            'compliance:frameworks:write','compliance:reports:read','findings:policies:read','findings:policies:write',
                            'findings:policies:delete','settings:billing:read','settings:billing:write')
 ORDER BY 1, 2, 3;
SELECT t.slug, r.name AS role, r.slug, r.hierarchy_level FROM roles r JOIN tenants t ON t.id = r.tenant_id
 WHERE NOT r.is_system AND (lower(btrim(r.slug)) IN ('owner','admin','member','viewer') OR r.hierarchy_level > 79);

-- C11. API keys whose scopes name renamed or removed permissions
SELECT t.slug, k.name, k.scopes FROM api_keys k JOIN tenants t ON t.id = k.tenant_id
 WHERE k.status = 'active' AND EXISTS (SELECT 1 FROM unnest(k.scopes) s
   WHERE s LIKE 'agents:%' OR s LIKE 'integrations:pipelines:%');

-- C12. Path exclusions rewritten by 001290 (host + path prefix; duplicates of one rule merged)
SELECT t.slug, e.pattern, e.status FROM scope_exclusions e JOIN tenants t ON t.id = e.tenant_id
 WHERE e.exclusion_type = 'path' ORDER BY 1, 2;

-- C13. Wildcard scope targets: after the upgrade "*.x" also covers "x"
SELECT t.slug, s.pattern FROM scope_targets s JOIN tenants t ON t.id = s.tenant_id
 WHERE s.pattern LIKE '*.%' AND s.status = 'active' ORDER BY 1, 2;

-- C14. Outbound webhooks, scope schedules and scan sessions that are dropped
SELECT (SELECT count(*) FROM webhooks) AS webhooks, (SELECT count(*) FROM scan_schedules) AS scope_schedules,
       (SELECT count(*) FROM scan_sessions) AS scan_sessions;

-- C15. Platform administrators: all deactivated, keys revoked. email_has_user_account = f can be revived with -link
SELECT a.email, a.role, a.is_active,
       EXISTS (SELECT 1 FROM users u WHERE lower(u.email) = lower(a.email)) AS email_has_user_account
  FROM admin_users a ORDER BY a.role, a.email;

-- C16. Organizations with an IP allowlist (enforced)
SELECT slug, settings->'security'->'ip_whitelist' AS ip_allowlist FROM tenants
 WHERE jsonb_array_length(COALESCE(settings->'security'->'ip_whitelist', '[]')) > 0;

-- C17. Organizations with allowed email domains (enforced for invitations, new users, SCIM, SSO JIT)
SELECT slug, settings->'security'->'allowed_domains' AS allowed_domains FROM tenants
 WHERE jsonb_array_length(COALESCE(settings->'security'->'allowed_domains', '[]')) > 0;

-- C18. Organizations with "Require two-factor authentication" (enforced at next sign-in)
SELECT t.slug, count(m.*) AS members FROM tenants t LEFT JOIN tenant_members m ON m.tenant_id = t.id
 WHERE (t.settings->'security'->>'mfa_required')::boolean IS TRUE GROUP BY t.slug;

-- C19. SSO providers with just-in-time provisioning but no verified domain (JIT refused)
SELECT t.slug AS org, 'oidc:' || p.provider AS provider, p.display_name
  FROM tenant_identity_providers p JOIN tenants t ON t.id = p.tenant_id
 WHERE p.is_active AND p.auto_provision
   AND NOT EXISTS (SELECT 1 FROM verified_domains d WHERE d.tenant_id = p.tenant_id AND d.status = 'verified')
UNION ALL
SELECT t.slug, 'saml', s.idp_entity_id FROM saml_providers s JOIN tenants t ON t.id = s.tenant_id
 WHERE s.enabled AND s.auto_provision
   AND NOT EXISTS (SELECT 1 FROM verified_domains d WHERE d.tenant_id = s.tenant_id AND d.status = 'verified');

-- C20. Commands in flight (let them finish before stopping the sensors)
SELECT status, count(*) FROM commands WHERE status IN ('pending','acknowledged','running') GROUP BY status;
```

</details>
