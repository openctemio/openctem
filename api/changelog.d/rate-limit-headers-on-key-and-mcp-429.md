### Added: rate-limit headers on the API-key and MCP 429s, and RateLimit-* names on every rate limiter

- A request refused by the per-key hourly limit of an `oct_` API key, or by the per-connection limit of the MCP endpoint, now carries `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` (and the `X-RateLimit-*` names). Before, those two 429s had no headers, so a client could not tell how long to back off.
- Every other rate-limit middleware now also sends the `RateLimit-*` names next to `X-RateLimit-*`. `RateLimit-Reset` is the number of seconds until the allowance is full; `X-RateLimit-Reset` stays a Unix timestamp. The `X-RateLimit-*` names are kept for one deprecation window and will then be dropped.
- Handler-level 429s that are cool-downs or one-at-a-time guards (a running export, a dashboard rebuild, a preview budget) are unchanged: they carry the error body only.
