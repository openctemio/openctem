### Fixed: the Compose stack pulls the images a release publishes

- `api/deploy/docker-compose.yml` defaulted the web console to
  `ghcr.io/openctemio/ui`, a name v0.9.0 is not published under, so
  `docker compose up` from a clean checkout failed. The API, web, job signer
  and gateway now default to `ghcr.io/openctemio/openctem-api`,
  `openctem-web` and `openctem-gateway` (the gateway also falls back to the
  file's release when `OPENCTEM_VERSION` is unset). API CI fails when the
  stack names an image the release workflow does not publish.
- The sensor gRPC overlay (`docker-compose.sensor-passthrough.yml`) no longer
  builds a gateway locally: the published gateway image has the layer4 module.
- **Upgrade note:** drop `API_IMAGE`/`UI_IMAGE` from `.env` if you set them to
  the new names; set them only to run v0.8.0 or earlier with this file.

### Security: least privilege for every Compose service

- Redis ran as root (a `sh -c` command skips the image's drop to the `redis`
  user); it now starts through the image's entrypoint and runs as uid 999.
  Existing `redis-data` volumes are re-owned on the first start.
- Postgres, Redis and the one-shot jobs (`datastore-tls`, `db-roles`,
  `migrate`) drop every capability and add back only what their entrypoints
  need; the gateway, `migrate`, `db-roles` and `datastore-tls` run with a
  read-only root filesystem; `datastore-tls` has no network. The Redis
  healthcheck reads the password from `REDISCLI_AUTH` instead of argv.

### Fixed: large uploads and feed imports no longer fill a 100 MB tmpfs

- The API's `/tmp` was a 100 MB in-memory tmpfs, but finding imports (up to
  110 MB) and form uploads are spooled there and feed bundles are staged
  there. It is now the `api-tmp` volume (on disk, not counted against the
  memory limit).

### Changed: memory limits for every long-running Compose service

- Postgres (`POSTGRES_MEMORY_LIMIT`, default 4g) and Redis
  (`REDIS_MEMORY_LIMIT`, 1g) get limits like the other services, the job
  signer gets 256m and log rotation, and the API sets `GOMEMLIMIT`
  (`API_GOMEMLIMIT`, 1600MiB, about 80% of its 2g limit) so the Go runtime
  collects garbage before the limit kills it.
- The web console runs under an init process, waits for a healthy API, and the
  gateway waits for a healthy web console.
