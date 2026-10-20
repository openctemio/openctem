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
| `api/deploy/docker-compose.yml` | The supported Compose deployment: gateway (one HTTPS port), web, API, PostgreSQL and Redis with TLS, and the one-shot `datastore-tls`, `db-roles` and `migrate` services |
| `api/deploy/backup.sh` | Backup (`backup`), restore check (`verify`) and restore (`restore <dir> --yes`) of that stack; encrypts with age when `BACKUP_AGE_RECIPIENT` is set (decrypt with `BACKUP_AGE_IDENTITY`) |
| `api/deploy/docker-compose.backup.yml` | Optional overlay: WAL archiving and scheduled full/differential backups to S3-compatible storage, an SFTP host or a local path ([guide](backup-and-restore.md)) |
| `api/deploy/gateway/` | Gateway Caddyfile, TLS modes, entrypoint and `smoke-test.sh`. `planes.caddy` is generated from the API's plane table: do not edit it by hand |
| `deploy/allinone/` | The all-in-one image (`ghcr.io/openctemio/openctem`): API, web, platform console and gateway in one container |

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
`vX.Y.Z` tag: `ghcr.io/openctemio/openctem-api`, `openctem-web`,
`openctem-console` (the platform console), `openctem` (all-in-one),
`openctem-gateway`, `migrations`, `seed` and `admin-cli`.

## Production

The supported deployments are `api/deploy/docker-compose.yml`, the all-in-one
image and the Helm chart; the API-only and web-only Compose files are removed.
`make docker-prod` only prints how to start `api/deploy`. Operators follow
[docs.openctem.io/install](https://docs.openctem.io/install/).

In `api/deploy` the API starts only after the `migrate` one-shot service
succeeds (`depends_on: migrate: { condition: service_completed_successfully }`),
and `OPENCTEM_VERSION` tags every platform image, so the migrations always match
the API.

The API image runs in production mode unless `APP_ENV` says otherwise: an unset
`APP_ENV` means `production`. Check a configuration without starting anything:

```bash
docker run --rm --env-file api.env ghcr.io/openctemio/openctem-api:vX.Y.Z -check-config
# or, in api/deploy:
docker compose run --rm --no-deps api -check-config
```

If a migration fails midway, `golang-migrate` marks `schema_migrations.dirty` and
the API refuses to start. Recovery is in the
[runbook](safe-deploy-and-migrations.md#dirty-migration-recovery). Never set
`SKIP_SCHEMA_CHECK=true` in production.

### Platform console

The platform administration console is its own service (`console`, image
`ghcr.io/openctemio/openctem-console`), served at the **root of its own site**
and reachable only from private networks by default (RFC-022 revision 21).
There is no `/admin` path on the main site. Four settings, also taken by
`setup.sh`:

| Setting | `setup.sh` | Default | Meaning |
|---------|------------|---------|---------|
| `OPENCTEM_ADMIN_SITE` | `--admin-site` | `port` | `port`: `https://<OPENCTEM_HOSTNAME>:<OPENCTEM_ADMIN_PORT>/`; `host`: `https://<OPENCTEM_ADMIN_HOST>/`; `off`: no console site |
| `OPENCTEM_ADMIN_HOST` | `--admin-host` | empty | The console's own DNS name (e.g. `admin.example.com`), host mode |
| `OPENCTEM_ADMIN_PORT` | `--admin-port` | `8443` | The console's port, port mode; any free port but 80, 443 and `GATEWAY_HTTPS_PORT` |
| `OPENCTEM_ADMIN_ALLOWED_CIDRS` | `--admin-cidrs`, `--admin-public` | loopback, RFC 1918, IPv6 ULA | Client networks that get past the console site; everyone else gets 403. The API checks the same list (`ADMIN_ALLOWED_CIDRS`) |

Optional: `OPENCTEM_ADMIN_BIND` publishes the console port on one interface
only (a private or VPN address); a published container port is not filtered
by the host firewall.

**For production, use host mode** (`./setup.sh <host> --admin-host
admin.example.com`): only a separate host name isolates the console from the
main site completely in the browser. Port mode is the default because it needs
no DNS; the port number itself is not a security control (the controls are the
separate origin, the network allow-list, the console's own sign-in and second
factor, step-up and the audit log). Never publish the console through a public
tunnel without an identity-aware access proxy in front of it.

How it is wired: the gateway's console site sends every request to the
`console` service; the console proxies its API to the API's internal console
listener (`ADMIN_LISTEN_ADDR=<api>:8081`, never published) through
`ADMIN_API_URL`. The main site answers 404 for `/api/v1/admin`, the web app has
no console route and refuses to proxy the console API, and the console has no
tenant route.

From a VPS, use your VPN or an SSH tunnel: `ssh -L 8443:127.0.0.1:8443
you@server`, then open `https://localhost:8443/`. A platform identity
provider's redirect URI is `<console origin>/login/callback`.

The all-in-one image runs the console too: publish `-p 8443:8443` (or set
`OPENCTEM_ADMIN_SITE=host` and `OPENCTEM_ADMIN_HOST`).

### All-in-one image: process isolation

The all-in-one image runs the API, the web console, the platform console and
the gateway in one container. Started as root (the image default), its
supervisor (`deploy/allinone/supervise.sh`) only prepares `/data` and starts
each process under its own uid, with no capabilities and (except the gateway,
whose Caddy binds 443 through a file capability) `no-new-privileges`:

| process | uid | environment | writable |
|---|---|---|---|
| API | 1002 `openctem-api` | everything except the schema owner's credentials | `/data/attachments`, `/data/sensor-ca` |
| web console | 1001 `nextjs` | its own `NEXT_*`, cookie and legal settings, `BACKEND_API_URL` | its `.next/cache` |
| platform console | 1003 `openctem-console` | the same, plus `ADMIN_API_URL` | its `.next/cache` |
| gateway | 1004 `openctem-gateway` | `OPENCTEM_*`, TLS, ACME, proxies | `/data/gateway`, `/data/ca`, `/config` |
| job signer | 1005 `openctem-signer` | `SIGNER_*` only | `/data/signer` (key and ledger, 0700: the API cannot read them; it reaches the signer through a group-shared socket) |

The lists are in `deploy/allinone/child-env.sh`. No database password,
`APP_ENCRYPTION_KEY`, `FINGERPRINT_KEY` or JWT secret reaches the web, console
or gateway process, and the schema owner's credentials (`DB_MIGRATE_*`,
`DATABASE_MIGRATE_URL`) reach no process at all: the supervisor runs the
start-up migrations itself, passes the password to `psql` and `migrate` in
`PGPASSWORD` (never on a command line, so never in `ps`), and drops it before
starting anything. A process cannot read another's environment or files. The
gateway's admin API is a unix socket only its uid can open, not
`127.0.0.1:2019`.

What stays shared, because every process is in one network namespace: any of
them can open the API's listeners on loopback, including the console listener
(`ADMIN_LISTEN_ADDR`), and the API trusts the client address loopback callers
forward. A compromised web process can therefore reach the console API as if
from an allowed network; it still needs a platform administrator's session.
Run the split Compose deployment (or the Helm chart) when that matters,
always for a multi-tenant service.

Started as a non-root uid (`--user 1001`, or a Kubernetes `runAsNonRoot` policy
without root), every process runs as that uid and the supervisor logs a
warning: the environment lists still apply, but one process can read
another's memory and environment. That mode is one trust domain, fit for
evaluation and small single-tenant installs only.

**Upgrading** from an image that ran everything as uid 1001: the supervisor
moves the gateway's storage from `/data/caddy` to `/data/gateway/caddy`
(certificates, the internal CA the sensors trust, the ACME account) and gives
each directory its new owner, once. In TLS mode `files`, the certificate and
key under `/certs` must be readable by uid 1004. To go back to an older image,
move `/data/gateway/caddy` back to `/data/caddy` and change the owner of
`/data` to 1001 first.

### Health page and host operations

The platform console has a read-only **Monitoring > Health** page (platform administrators
only): service health, free space of the data volumes and the database size,
the age of the last backup, certificate expiry, and the running version with
the version-check result. When free space drops below 20% (warning) or 10%
(critical), the backup is older than 26 hours, or a certificate is close to
expiry, the platform administrators are emailed through the system mailer and
a metric and a log line are written. Backup, restore, upgrade and key rotation
stay in the Ansible kit's command line over SSH; the kit installs no host web
console. An operator who wants one can follow the optional recipe in
[RFC-114](../rfcs/RFC-114-system-page.md), appendix A.

### Outbound connection: the version check

The version check is **on by default**. Once a day the API downloads one public
file, the signed release feed, from GitHub
(`https://github.com/openctemio/openctem/releases/latest/download/openctem-releases.json`),
and compares it with its own version on the server; the platform console then
shows newer releases and security releases that affect the instance. The
request sends nothing about the instance (no id, no version, no counts, no
cookies); GitHub sees the server's IP address, as for any download.

- Turn it off: `VERSION_CHECK_ENABLED=false` (in `api/deploy/.env`). No request
  is made at all.
- Air-gapped or no internet access: leave it on or off; without access it fails
  silently and retries weekly. Download `openctem-releases.json` from the latest
  release on a connected machine and import it in the console (Monitoring > Software
  updates, super administrator). It is verified exactly like the online check.
- Internal mirror: `VERSION_CHECK_URL=https://...` (https only). The signature,
  not the host, is trusted; a mirror on a private address also needs the private
  egress allowlist (`OPENCTEM_HTTPSEC_*`).

Details: [version check](../architecture/version-check.md).

### Gateway user

The gateway runs as uid/gid 1000 (as in the Helm chart), not as root, from the
`ghcr.io/openctemio/openctem-gateway` image: Caddy with the standard and layer4
modules, built with the release's Go toolchain. In `api/deploy` it binds 443
(and 80 with the redirect overlay) through the namespaced sysctl
`net.ipv4.ip_unprivileged_port_start=0`, so it keeps `no-new-privileges` and
holds no capability.

**Upgrading from a release whose gateway ran as root** (the `caddy` image): the
`gateway-data` and `gateway-config` volumes and the `./ca` directory hold
root-owned files that a non-root gateway cannot read. The one-shot
`gateway-init` service changes their owner to 1000:1000 on every `up` (offline,
`CHOWN` and `DAC_READ_SEARCH` only; nothing to do once they are right), so
`docker compose up -d` is enough. Where that service is not used (your own
Compose file, a copied volume), change the owner once by hand before starting
the new gateway:

```bash
docker compose run --rm --no-deps --user 0 --entrypoint chown gateway -R 1000:1000 /data /config /ca
```

The gateway refuses to start while `/data` or `/config` holds a file it does
not own, and its log prints that command. The certificates, the internal CA
(and so the root sensors trust) and the ACME account are kept: only their
owner changes.

## Make targets

```bash
make docker-down         # stop the development compose stack
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
