### Security: the all-in-one image runs each process under its own user with only its own settings

- The supervisor starts as root only to prepare `/data`, then runs the API, the web console, the platform console and the gateway each under its own uid (1002, 1001, 1003, 1004), without capabilities. A process can no longer read another's environment or files.
- Each process gets only its own environment: no database password, `APP_ENCRYPTION_KEY`, `FINGERPRINT_KEY` or JWT secret reaches the web console, the platform console or the gateway, and the schema owner's credentials (`DB_MIGRATE_*`, `DATABASE_MIGRATE_URL`) reach no process.
- The start-up migrations pass the schema owner's password in `PGPASSWORD` instead of the `psql`/`migrate` command line, so it no longer shows in `ps`.
- The gateway's admin API is a unix socket only the gateway's uid can open (new `OPENCTEM_CADDY_ADMIN`; the split deployment keeps `127.0.0.1:2019`).
- Behaviour change: the gateway's storage moves from `/data/caddy` to `/data/gateway/caddy` on the first start (automatic). In TLS mode `files` the key under `/certs` must be readable by uid 1004. Started as a non-root uid (`--user 1001`), the image keeps working as one trust domain and logs a warning. See `api/docs/deployment/docker.md`, "All-in-one image: process isolation".
