### Behaviour change: every closed finding records why it closed and how that was proven

- A closed finding now carries a `closure_reason` and, when resolved, a
  `verification`, replacing `resolution_method` (removed). Resolved:
  `fixed`, `mitigated`, or `obsolete_asset` / `obsolete_source` /
  `obsolete_rule` (it went away without a fix). False positive: the five VEX
  `not_affected` justifications, `detection_error`, `test_or_example_code`.
  Accepted: `risk_accepted`, `compensating_control`, `wont_fix`,
  `no_fix_available`. Duplicate: `duplicate`, `correlated`. Verification:
  `covered_scan`, `retest`, `source_reported`, `vex_statement`,
  `security_review`, `attested`, `none`. Both are in the finding API response.
- **Requesting a false positive or an accepted risk now needs a reason**:
  `POST /findings/{id}/approvals` takes `closure_reason` (required); the web
  request dialog asks for it. The approval applies that reason. A resolve
  (`PATCH /findings/{id}/status`, bulk) may name `closure_reason`
  `fixed` (default) or `mitigated`.
- **MTTR counts remediations only**: findings resolved because their asset,
  source (a retired CI pipeline) or rule (the license policy no longer flags
  the package) went away are left out of MTTR, the risk snapshot's
  closed-today, the executive summary and the risk velocity fix count.
- Existing closed findings are backfilled from what `resolution_method`
  recorded; everything else becomes `unknown` (never guessed), and a resolved
  finding of unknown reason still counts in MTTR as before.
- Migrations `002270_finding_closure_columns` (columns), `002271_finding_closure_backfill`
  (batches of 1000 rows, each committed), `002272_finding_closure_trigger` (trigger and
  CHECK `NOT VALID`), `002273_finding_closure_validate`, `002274_finding_closure_drop_resolution_method`.
- **Upgrade note:** the migration drops `findings.resolution_method`; stop the
  API while it runs (old code reads that column).
