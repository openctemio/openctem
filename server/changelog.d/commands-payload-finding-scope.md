### Security: the commands list no longer shows a finding's content outside the caller's data scope

- `GET /api/v1/commands` returned every command's payload and result to any member with `commands:read` (the Viewer role included). An AI analysis job carries the analysed finding's text in its payload and the worker's answer in its result, so a member could read findings they may not open, which the AI run routes refuse.
- A command about a finding (an `analyze` job, through its run; a retest's check or reach command; a `validate` job) is now listed without its payload and result unless the caller holds `findings:read` and the finding is in their data scope. An analysis job whose run cannot be found is shown to nobody. Its logs (`GET /api/v1/commands/{id}/logs`) follow the same rule, now for analysis jobs too (404). Commands about no finding are unchanged; the targets of scan commands stay under the existing scan-read data-scope work.
- Migration `20261116162542_ai_runs_command_index`: a partial index on `ai_runs (command_id)`, built concurrently, for that lookup. No data change.
- Docs: server/docs/architecture/ai-analysis.md
