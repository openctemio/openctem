### Changed: CI runs the API and web test suites in parallel shards

- API tests, the least-privilege tests and the web Vitest suite run as parallel shards, and lint runs in its own job, so a push waits for the slowest shard instead of the whole suite.
