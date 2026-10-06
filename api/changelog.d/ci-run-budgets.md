### Security: per-run report cap and per-pipeline run rate for CI

- A CI run accepts at most 200 reports; one more answers `409`.
- A CI pipeline may start at most 300 runs an hour; beyond that the token exchange is refused and audited (`ci_run.token_refused`, reason `pipeline_rate`). Other pipelines of the repository are not affected.
- A test now pins that a secret a CI run uploads unmasked (as its value or in the snippet) is stored nowhere in clear, and never reaches the audit log.
