### Added: one command prepares a Compose install

- `api/deploy/setup.sh <host name> [--acme you@example.com]` writes `.env` from `.env.example` with freshly generated secrets (database roles, Redis, `APP_ENCRYPTION_KEY`, `METRICS_TOKEN`), mode 0600. It never overwrites an existing `.env` and never prints a secret. CI renders the stack from it.
- `OPENCTEM_VERSION` is optional: the compose file defaults to the release it ships with (kept in step by `sync-versions.sh`).
