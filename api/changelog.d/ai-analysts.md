### Added: AI analysts, service accounts that triage like a person with accountable owners

- An AI analyst is a service account with an AI profile (`ai_analysts`): it calls the same finding commands as a person, with its own role and data scope, and its changes go through the same approvals, audit and notifications. It never signs in, never approves, never holds full data access and is not a seat.
- Presets `ai-analyst-suggest` (read, comment, approval requests) and `ai-analyst-triage` (also status, duplicates, severity, assignment), created from role templates and assigned under the role grant ceiling. A fixed deny list keeps approve, verify, delete, export, reveal, bulk and administration with people whatever the role says.
- Every analyst has accountable owners, people or teams (`ai_analyst_owners`). Its effective permissions never exceed what they hold; it pauses when no owner is active or the 90-day attestation runs out (checked at run start and by an hourly sweep).
- Everything an analyst does carries its provenance: timeline rows are labeled `ai` by the database and carry the run, model, prompt and accountable owners; audit rows carry the same under `metadata.ai`.
- `ai_runs` records every run (analyst, accountable snapshot, model, prompt, digests, usage); one live run per subject and use case.
- API: `/api/v1/ai/analysts` (list, create, owners, preset, attest, pause, resume, disable, delete), `/api/v1/ai/runs/{id}`, `/api/v1/findings/{id}/ai/runs`. Migration `003515_ai_analysts`; no operator action.
