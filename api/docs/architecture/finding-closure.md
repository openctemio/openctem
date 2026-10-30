# Finding closure: when a finding closes by itself

Design: research note "finding closure policy" (local), RFC-040 (mutual
distrust), RFC-039 (continuous retest). Code: `internal/app/ingest/coverage_autoresolve.go`,
`internal/app/ingest/coverage_targets.go`, `internal/infra/postgres/finding_coverage_autoresolve.go`.

A finding closes by itself only on proof that **the same check looked again at
the same target over a healthy path and the issue is gone**. Everything weaker
(not seen, blocked, unreachable, another tool, a partial look) is an
observation that keeps the finding open.

## Coverage of one scan command

A completed scan command is evaluated once its reports are committed
(`EvaluateCommandCoverage`):

1. **The run.** The command completed with exit code 0, its result is not cut
   short, every report completed with nothing rejected, quarantined or in error,
   and every report names the same tool, which the reporting sensors declare.
   Reports must declare `coverage_type`; an absent value is never full.
2. **Per target.** When the command result carries `target_outcomes` (one
   outcome per target), coverage is decided per target: a target is covered
   only when its outcome is `done` and no coverage gap, unreached or refused
   entry of the result names its host. A run with `coverage_type` `partial`
   is accepted on these terms; `incremental` never is. A target without an
   outcome, a gap or unreached list shorter than its total, or unreadable
   metadata makes the target (or the run) not covered. A result without
   outcomes (an older sensor) proves coverage only when it is `full` and lists
   no gap, unreached or refused target.
3. **Covered assets.** The assets the reports touched, plus the assets with
   open findings of the same tool whose last sighting came from a command aimed
   at a covered target (same target string), filtered to the assets the covered
   targets reach (`coversLocated`). A scan that found nothing pushes an empty,
   command-bound report, so such a run is evaluated too.
4. **Candidates.** Open, non-repository findings of the tool on those assets,
   last seen by a report of the same tool under the same scan profile, not
   reported by this run (its receipt decides), not from a protected source
   (pentest, manual, bug bounty, red team). Secrets are marked not observed,
   never resolved. A candidate whose last sighting ran another template release
   is marked stale, not resolved.
5. **Guard and mode.** The blinding guard holds a run that would close too
   many of the open findings at once. `INGEST_COVERAGE_AUTO_RESOLVE` decides
   what happens: `off`, `dry_run` (default: logged, receipt and audit only) or
   `enforce`.

## What never counts as a clean look

| Outcome of a target | Why it proves nothing |
|---|---|
| `failed` unreachable, timeout, `stopped_answering` (host breaker) | the check did not run to the end against the target |
| `failed` edge blocked or challenged (gap `blocked`) | an edge answered in place of the service |
| `failed` rate limited (gap `rate_floor`) | the host pushed back; checks were skipped |
| `failed` sensor network fault (gap `proxy_unavailable`, control probe failed) | the sensor's own path failed; nothing is known about the target |
| `skipped` refused or excluded | the scanner never saw the target |
| `unfinished` | the job's time ended before the target finished |
