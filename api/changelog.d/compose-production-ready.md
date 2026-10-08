### Changed: the Compose deployment uses the release image names, SSO lands on the public URL, backups and monitoring work out of the box

- `api/deploy/docker-compose.yml` pulls `ghcr.io/openctemio/openctem-api` and
  `openctem-web` (the names every release publishes); `.env.example` pins v0.9.0.
- The API gets `OAUTH_FRONTEND_CALLBACK_URL=<OPENCTEM_PUBLIC_URL>/auth/callback`
  (SSO logins went to `http://localhost:3000`) and `METRICS_TOKEN` (empty: metrics off).
- The sensor and SDK "latest" versions default to the release the API was built
  with instead of stale pins; the API drops every Linux capability; API, web and
  gateway have memory limits (`API_MEMORY_LIMIT`, `WEB_MEMORY_LIMIT`, `GATEWAY_MEMORY_LIMIT`).
- New `api/deploy/backup.sh`: `backup` (database, attachments, gateway CA, .env;
  retention; node-exporter metrics for the BackupStale/BackupFailed alerts),
  `verify` (restore into a throwaway Postgres and compare row counts) and
  `restore <dir> --yes`.
- New `deploy/observability/docker-compose.openctem.yml` overlay: monitors the
  shipped stack (network, `web` service, Postgres TLS, Redis over TLS verified
  against the datastore CA). The Postgres monitor role now gets CONNECT, which the
  least-privilege roles revoke from PUBLIC (`pg_up` was 0).
