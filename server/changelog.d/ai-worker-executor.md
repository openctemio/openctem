### Added: an AI agent can run on the organization's AI workers

- An AI agent runs built in (the platform calls the model) or on the organization's AI workers: `PUT /api/v1/ai/agents/{id}/executor` with `builtin` or `tenant_worker` (`service_accounts:manage` and a recent sign-in, audited `ai_agent.executor_changed` with the value before and after).
- For an AI agent on AI workers, `POST /api/v1/findings/{id}/ai/analyze` runs the same checks as a built-in run (AI off for the organization, use case, data scope, data class ceiling, masked bundle with the mapping kept on the platform), then answers 202 with a queued run and sends one analysis job (`analyze` command) whose payload is the validated `openctem.analyze/v1` job (masked `bundle.text`, budgets, model policy, a 15-minute deadline) next to `required_capabilities: ["analyze.<kind>"]`. A bundle over the job size limit is shortened by its encoded size, and the job says so. Audited `ai_agent.analysis_job_queued`, without the bundle text.
- A run on an AI worker always ends: past its deadline, or when its job expired, failed, was canceled or is gone, the `ai-worker-run-sweep` controller ends it `failed` (`deadline_exceeded`, `worker_error`, `worker_unavailable`) or `canceled` within a minute and cancels a job still open. Applying a worker's result comes in a later release.
- Migrations 20261113063356 (`ai_runs.injection_suspected`, boolean, default false) and 20261113063414 (index `idx_ai_runs_worker_live`, built concurrently): schema only, no data changes.
- Docs: server/docs/architecture/ai-analysis.md ("Runs on an AI worker"), server/docs/rfcs/RFC-131-ai-analysis.md §5

### Security: analysis jobs reach only an explicit AI worker grant

- An `analyze` command is handed only to a sensor of the organization whose grant is the `ai-worker` profile (job types exactly `analyze`). A sensor on the `legacy-broad` grant that advertised an `analyze.<kind>` capability could have claimed one; it now gets none, by poll or by id, and a claim that reads no grant withholds analysis jobs.
- Docs: server/docs/architecture/sensor-pairing.md ("The AI worker profile")
