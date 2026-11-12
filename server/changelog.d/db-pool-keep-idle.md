### Changed: the API keeps its database connections open between bursts

- `DB_MAX_IDLE_CONNS` now defaults to `DB_MAX_OPEN_CONNS` (25) instead of 5. With 5, every burst of more than five concurrent queries (one page load fans out to many) closed the extra connections and reopened them on the next burst, each with a TCP and SCRAM handshake and a new PostgreSQL server process. On a restored copy of the UAT database at 10 concurrent requests, `GET /me/bootstrap` went from 455-500 ms to 183-266 ms median and twice the throughput; small reads lost about half their p95.
- **Upgrade note:** PostgreSQL may now hold up to `DB_MAX_OPEN_CONNS` idle connections from each API replica. Set `DB_MAX_IDLE_CONNS` explicitly to keep the old behaviour.
