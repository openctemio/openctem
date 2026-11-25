### Added: AI worker results are applied

- When an AI worker completes an analysis job, the platform applies its result as the AI agent, through the same checks, unmasking and governance as a built-in run. Every row the AI agent writes names the run, the worker, the model and model family, the result digest and the evidence it cited; each result is audited (`ai_agent.analysis_result_applied` / `ai_agent.analysis_result_refused`).
- The result is taken once, for the run named in the platform's own job, within the run's deadline; a replay, another job's result, another organization or a late result applies nothing. A change anyone made to the finding after the job was sent turns the AI agent's changes into comments.
- Lowering risk stays a request a person decides. Worker text is stored as plain text (markdown and HTML escaped), and a suggestion whose text matches a prompt-injection pattern is only a comment.
- The result contract gains an optional `usage.model_family`. Runs record `outcome`, `action_log`, `model_family` and `subject_row_version` (migration `20261125075517_ai_worker_results`, schema only).
- Docs: server/docs/architecture/ai-analysis.md

### Security: analysis jobs end only by a signed request under the lease epoch

- `complete` and `fail` of an `analyze` command are accepted only from a request signed with the AI worker's own key that states its lease epoch; a bearer key, an unsigned request or a missing epoch is answered `command-not-found`. AI workers paired with a key (the default) are unaffected.
- Docs: server/docs/architecture/ai-analysis.md

### Added: a pause switch and limits for changes AI agents make without a person

- `GET/PUT /api/v1/organization/settings/ai/autonomy`: pause every change an AI agent makes without a person at once, and limit them per hour and per day (defaults 100 and 500; `null` is unlimited). Pausing and lowering are one click; resuming, raising or removing a limit needs a recent sign-in, is audited critical and owners and administrators are told. Applies to the built-in executor and to AI worker results.
- Docs: server/docs/architecture/ai-autonomy.md
