### Security: a failed connection test no longer shows ids or the upstream error

- A failed connection test (ticketing, SCM, notification channels) stores a code (`status_code`, one of the `INTEGRATION_*` codes) and a safe sentence instead of the raw error, which could name the integration by id, carry an internal address from a dial error or an upstream response body. The cause is logged with the integration's ids. Migration `003405` adds `integrations.status_code` (empty for existing rows); reads clean older stored texts the same way as error responses.
- `POST /api/v1/integrations/test-credentials` answers with `code` on failure.
