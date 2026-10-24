### Fixed: API exits when its listener fails; write timeout above request timeout; single-run controllers hold a lease
- The API process now exits with a non-zero status when the HTTP listener cannot start (port in use, bad TLS material), so the orchestrator restarts it. Before, it stayed alive running background controllers with nothing listening.
- `SERVER_WRITE_TIMEOUT` now defaults to `SERVER_REQUEST_TIMEOUT + 5s` (35s) instead of 15s: a handler running between 15s and 30s used to finish while the client saw a closed connection instead of the `503` timeout answer. The API logs a warning at startup when an explicit write timeout is not above the request timeout.
- The task-ticket push, DefectDojo sync, SCM sync, SAML certificate expiry notice and pending-scope settle controllers run on one API replica at a time (controller lease), so several replicas no longer open duplicate tracker issues, send duplicate notices or repeat remote syncs.
- The scheduled SCM sync reads every integration in pages instead of only the first 1000.
- CI trust configuration `last_used_at` is written at most once a minute, so a burst of pipeline token exchanges no longer updates one row per exchange.
- Ingest job leases (claim, renew, stale release) use the database clock, as controller leases do, so replica clock skew cannot shorten a lease.
