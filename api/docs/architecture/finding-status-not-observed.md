# Finding observation and validation

Decided 2026-10-04 (decision O2, stale is not fixed); made fields beside the
status 2026-10-15 (research/154 D1). The status set and lifecycle:
[finding-status-lifecycle.md](finding-status-lifecycle.md). Code:
`pkg/domain/vulnerability/observation.go`.

The status answers "what is the next human action?". Two facts about a
finding are not actions and live beside it:

| Field | Values | Meaning |
|---|---|---|
| `observation_state` (API `observation`, filter `observation`) | `present`, `stale` | Stale: recent scans no longer report it, **but nothing proves the check ran against it** (no coverage proof). Stale is never fixed. |
| `validation_outcome` (API `validation`, filter `validation`) | `reproducible`, `not_reproducible`, none | The latest re-check verdict (a retest, the validation engine). |

They replace the statuses `not_observed` and `validated_fixed`. A finding is
now, for example, `in_progress` **and** stale **and** not reproducible; before,
going stale lost its work state.

## Observation

| Property | Value |
|---|---|
| Counted as fixed | Never. The status stays open, so fix-rate and MTTR exclude it and its SLA keeps running. |
| Who sets stale | Only the platform: feature-branch expiry (`ExpireFeatureBranchFindings`) and branch-only expiry, a stale CI source (`MarkStaleSourceFindings`), template drift in coverage auto-resolve (`MarkCoverageNotObserved`), the software matcher when a version is no longer installed. Each marks only open findings that are present. |
| Back to present | Any sighting: the ingest upsert and re-sighting paths, a retest that still matches, the software matcher matching again. |
| Closing a stale finding | A covered scan still resolves it (coverage proof), a retest with auto-resolve, or a `findings:verify` holder. |

## Validation

| Event | Status | `validation_outcome` |
|---|---|---|
| A retest confirms the fix, without `retest.auto_resolve` | unchanged | `not_reproducible` |
| A retest confirms the fix, with `retest.auto_resolve` | `resolved` (`fixed` / `retest`) | `not_reproducible` |
| A retest still matches | `resolved` → `confirmed` (regression), `fix_applied` → `in_progress`, otherwise unchanged | `reproducible` |
| The validation engine: not reproducible on new / confirmed / in progress | unchanged (a downgrade, `downgraded_at`) | `not_reproducible` |
| The validation engine: reproducible on fix_applied | `in_progress` | `reproducible` |

## Migration

`finding_status_dimensions` moves every finding in a retired status back to
the status its timeline shows it had before (else `confirmed`), sets the
dimension, writes a timeline entry (source `migration`, reason
`status_retired`), rewrites stored filter documents (saved views, remediation
campaigns), and replaces the status CHECK (validated in
`finding_status_dimensions_validate`). Live had no finding in either status.
