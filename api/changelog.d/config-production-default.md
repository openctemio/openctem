### Behaviour change: an unset APP_ENV means production; AUTH_PROVIDER defaults to local

- The API (and every image built from it, the all-in-one included) treats an
  unset `APP_ENV` as `production`, so a container started without configuration
  gets every production check (secrets, TLS to Postgres and Redis, Secure
  cookies, rate limits) and refuses to start without them, instead of running in
  development mode. `AUTH_PROVIDER` defaults to `local` (it was `oidc`).
- A secret that still holds example-file text (`openssl rand -hex 32`,
  `<CHANGE_ME...>`, `your-super-secret-...`) is refused at start-up in every
  environment, with a message naming the variable.
- New `server -check-config`: validates the configuration from the environment
  and exits (0 valid, 1 invalid) without connecting to anything; no secret is printed.
- `api/.env.example` now holds working development values (it held the literal
  `openssl rand -hex 32` as the encryption key, which stopped the API).
- **Upgrade note:** a development setup that relied on the old default must set
  `APP_ENV=development` (the shipped `.env.example` and `docker-compose.dev.yml`
  already do). A deployment that relied on `AUTH_PROVIDER` defaulting to `oidc`
  must set `AUTH_PROVIDER=oidc`.
