### Security: a CI run is bound to the job that exchanged its token

- Each CI run records the provider's job id from the verified OIDC token (GitHub `check_run_id`, GitLab `job_id`) next to the pipeline run id, attempt and actor login (migration `001110`, one column with a constant default).
- A run token is renewed only for that job and attempt: another job of the same pipeline, or a re-run, can no longer take over a running run's token; the attempt is refused and audited (`run_mismatch`).
- Every results upload is audited (`ci_run.results_uploaded`: finding count, tool label, job id; no finding content). Exchange audits carry the attempt, the job id and whether it was a renewal.
- The run view (`GET /api/v1/ci/runs/{id}`) returns `external_job_id`.
