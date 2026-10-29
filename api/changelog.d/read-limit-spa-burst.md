### Fixed: stepping through findings no longer hits "Too many requests"

- The per-user budget for authenticated `GET` requests (`RATE_LIMIT_READ_PER_MIN`) is now 600 a minute, with the same burst (it was 120). A finding page sends about twenty reads on load, so the sixth finding opened within a minute failed with 429, showed "Could not load this finding" and stacked three or four toasts. The limit stays per user, so colleagues behind one office address never share it, and writes and sign-in keep their own, stricter limits.
- A refused read now says how long to wait: `Retry-After` follows the limiter's rate instead of a fixed `1`.
- The web console retries a read refused with 429 once, after the server's `Retry-After` (at most 5 seconds, with jitter), before it reports an error, and every rate-limit message shares one toast. Writes are never repeated automatically.
- **Upgrade note:** an operator who set `RATE_LIMIT_READ_PER_MIN` keeps their value; remove it to get the new default.
