### Added: one environment variable registry; misspelled or unparseable variables stop startup

- `internal/config/env_registry.yaml` lists every environment variable the API, its tools, the web console, the gateway, the Compose stack and the all-in-one image read: type, default, required, secret, description. A test keeps it equal to what the code reads, including literal defaults.
- `api/.env.example` and the new `api/docs/configuration/environment-variables.md` are generated from it (`make env-docs`; a test fails when they are stale). `.env.example` now lists only what a development checkout sets (64 lines instead of about 490); everything else keeps its default.
- **Behaviour change:** startup refuses a variable under an API prefix (`SMTP_`, `AUTH_`, `SENSOR_`, ...) that is not registered but is within three edits of a registered name, with a "did you mean" hint (for example `SMTP_PASWORD`). Other unregistered names under those prefixes are logged as warnings. Kubernetes service-link variables are ignored.
- **Behaviour change:** a set API variable whose value does not parse as its type (`SERVER_PORT=abc`, `SENSOR_KEY_TTL=30d`, `RATE_LIMIT_ENABLED=yes`) now stops startup instead of silently using the default. Messages name variables, never values.
- `server -check-config` also lists which API variables are set (names only) and the warnings.
