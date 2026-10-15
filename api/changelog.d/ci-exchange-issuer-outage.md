### Fixed: a CI provider outage or key rotation no longer refuses CI jobs

- The CI provider's discovery document is now served stale (up to six hours,
  like its keys) when the provider cannot be reached. Before, every CI token
  exchange failed once the one-hour cache expired, even with the keys still
  cached. Concurrent refreshes wait for one fetch, and a failed fetch is not
  retried within 30 seconds.
- A token whose keys cannot be fetched (the provider is unreachable past that
  bound, or it has just rotated to a key not yet fetched) now gets `503
  CI_ISSUER_UNAVAILABLE` with `Retry-After: 30`, and nothing is claimed, so
  the job retries the same token. Before, it got the same `401` as a forged
  token.
