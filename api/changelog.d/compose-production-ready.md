### Changed: the Compose deployment sends SSO to the public URL; backups and monitoring work out of the box

- The API in `api/deploy/docker-compose.yml` gets
  `OAUTH_FRONTEND_CALLBACK_URL=<OPENCTEM_PUBLIC_URL>/auth/callback` (SSO logins
  went to `http://localhost:3000`) and `METRICS_TOKEN` (empty: metrics off). It
  drops every Linux capability; API, web and gateway have memory limits
  (`API_MEMORY_LIMIT`, `WEB_MEMORY_LIMIT`, `GATEWAY_MEMORY_LIMIT`).
- `versions.yaml`: the newest sensor is v0.11.0 (it said v0.6.4) and the oldest
  supported is v0.9.0 (protocol v1 is retired, older sensors cannot connect);
  the newest SDK is v0.18.0. The Sensors page, install snippets and Compose
  defaults follow.
- New `api/deploy/backup.sh`: `backup` (database, attachments, gateway CA, .env;
  retention; node-exporter metrics for the BackupStale/BackupFailed alerts),
  `verify` (restore into a throwaway Postgres and compare row counts) and
  `restore <dir> --yes`.
- New `deploy/observability/docker-compose.openctem.yml` overlay: monitors the
  shipped stack (network, `web` service, Postgres TLS, Redis over TLS verified
  against the datastore CA). The Postgres monitor role now gets CONNECT, which the
  least-privilege roles revoke from PUBLIC (`pg_up` was 0).
