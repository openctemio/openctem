### Behaviour change: a finding closed as out of scope is never counted or shown as fixed

- Findings closed because their asset was marked not ours or retired (closure reason `out_of_scope`) no longer count as remediated in MTTR, fix rate, program, CTEM cycle and risk snapshot figures.
- They leave the SLA (`sla_status = not_applicable`) instead of counting as met or missed; migration `out_of_scope_sla_not_applicable` backfills existing ones. Re-including the asset reopens them with the deadline they had.
- Every close and reopen by the scope effects reconciler writes a `finding.status_changed` audit entry naming the exclusion and its kind (or the "not ours" decision); high severity for critical, P0 or KEV findings.
- The outbound ticket push now runs for these moves. A linked Jira issue gets a comment and is not moved to a done status; a linked GitHub issue is left open.
- A permanent not ours or retired exclusion that would close open critical, P0 or KEV findings is refused with `EXCLUSION_CLOSES_CRITICAL_FINDINGS` (409, details `critical_findings`) until the request carries `confirm_critical`. The bulk preview returns `critical_findings`; both out-of-scope dialogs ask for the confirm.
