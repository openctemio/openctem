### Removed: secret-bearing dev flags and the broken dev admin script

- `cmd/encrypt-credentials` reads `DATABASE_URL` and `APP_ENCRYPTION_KEY` from the environment only; the `-db` and `-key` flags (which put the database password or master key in argv) are gone.
- `scripts/dev-setup-admin.sh` is removed (it built a shell command from its inputs and could not run); use `bootstrap-admin` with `-no-backup`.
- Development compose (`docker-compose.yml`, `docker-compose.dev.yml`): ports bind to 127.0.0.1, `DB_PASSWORD` is required (no default), and the header no longer says production.
- `scripts/migrate.sh` loads `.env` with `set -a; . ./.env` and `down-all` needs `--yes`; `cmd/seed -clean` needs `-yes`.
