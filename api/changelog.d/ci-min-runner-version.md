### Behaviour change: CI runners below the minimum supported version are refused

- A CI job whose runner reports a sensor version below `SENSOR_MIN_VERSION` now gets `403 RUNNER_OUTDATED` at the OIDC exchange (after its token verified and was admitted); the refusal is audited (`ci_run.token_refused`, reason `runner_outdated`). Before, the run was accepted and its pipeline only shown as degraded.
- A client that reports no sensor version is still admitted.
- **Upgrade note:** pipelines pinned to an old sensor image must update it before `SENSOR_MIN_VERSION` is raised.
