### Added: one CI run for the parallel scan jobs of a pipeline

- `POST /api/v1/ci/oidc/exchange` takes `aggregate: true`: every capability job of one pipeline run (same pipeline, provider run id, attempt and commit, all from the verified OIDC token) joins one run with its own upload token, and a final job asks for the verdict on all of them (RFC-051 §4.1). The response says `aggregate`.
- A job joining never invalidates another job's token; a token without a pipeline run id cannot join; joins are audited. Expired job tokens are deleted by the CI retention job.
- Migration `001220` adds `ci_runs.aggregate` and `ci_run_tokens`.
