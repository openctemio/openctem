### Added: rate-limit headers on every 429, including API-key and MCP limits

- A request refused by the per-key hourly limit of an `oct_` API key, or by the per-connection limit of the MCP endpoint, now carries `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` (and the `X-RateLimit-*` names). Before, those two 429s had no headers, so a client could not tell how long to back off.
- Every other limiter now also sends the `RateLimit-*` names next to `X-RateLimit-*`. `RateLimit-Reset` is the number of seconds until the allowance is full; `X-RateLimit-Reset` stays a Unix timestamp. The `X-RateLimit-*` names are kept for one deprecation window and will then be dropped.
