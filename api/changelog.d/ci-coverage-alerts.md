### Added: CI coverage, stale sources and CI alerts

- `GET /api/v1/ci/coverage`: repository x capability (SAST, SCA, secrets, IaC) coverage from CI pipelines and daemon scans, within the caller's data scope, with gaps first, a summary and template drift. `PUT`/`DELETE /api/v1/ci/coverage/expectations/{id}` mark a repository as expected to be covered, so "never scanned" shows as a gap (audited).
- Findings whose only source is a stale or archived CI pipeline move to not observed (`source_stale`); a new sighting reopens them. `POST /api/v1/ci/pipelines/{id}/retire` (reason required) retires a pipeline and closes those findings as `source_retired`, audited and reopenable. Findings from pentest, manual, bug bounty and red team sources are never touched.
- Notification event types `ci.schedule_missed`, `ci.coverage_regression`, `ci.runner_outdated` (on by default) and `ci.gate_failing` (opt-in), sent once per pipeline or repository while the condition holds (migration `001082`).

### Behaviour change: findings only a stale CI pipeline reported become not observed

- Within 15 minutes of the upgrade, the CI alert job moves open findings whose only source is a CI pipeline that is stale or archived to not observed (`source_stale`), audited per pipeline (`ci_pipeline.stale_source_findings`). They are not resolved and reopen on the next sighting.
