### Changed: audit rows carry the request id; log records name their service

- An audit row written during a request now carries the request id and the client address (trusted-proxy rule applied) even when the code that wrote it did not pass them; until now most rows had neither. An explicit value still wins; background work records neither.
- Every application log record carries `service`, `version` and `env`.
