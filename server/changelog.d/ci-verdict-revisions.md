### Added: CI verdict revisions (groundwork, not active yet)

- Migration `20261125095958_ci_run_verdict_revisions` (additive): every CI gate verdict is also recorded as revision 1 in the append-only `ci_run_verdicts`, with what it was computed with (`ci_runs.policy_snapshot`) and the job that asked for it (`ci_runs.gate_job_id`), so a later decision can re-judge the stored run without a rescan. Re-judging itself is not wired yet.
- Docs: none (groundwork; the RFC-077 amendment comes with the wiring)
