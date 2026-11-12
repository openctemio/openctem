### Behaviour change: compliance results are control states, not findings

- Every benchmark check result (finding type `compliance`) is now stored as the latest state of its control on its asset, with its evidence (actual and expected value, the scanner's message, the audit file) and a history of every change (migration `20261108115557_compliance_check_state`: `compliance_check_states`, `compliance_check_results`, `compliance_posture`, `findings.compliance_level`).
- Only a FAILED result (and a WARNING, which needs a person) is a finding. A not-applicable and an error result are kept as states only and counted on the receipt as `compliance_state`; an error is no longer folded into not applicable.
- `findings.compliance_level` holds the benchmark level (CIS Level 1 or 2, a STIG category) read from the benchmark profile.
- A compliance finding's remediation group is its benchmark control (`control:<benchmark>:<control>`, key rules version 5): one fix of a control covers every asset. Compliance findings never join package or solution groups. Existing keys are derived again by the remediation key backfill.
- The dashboard maintainer keeps a per-asset benchmark posture (controls per result) for the pass rate.
- **Upgrade note:** existing compliance findings are not changed by the migration; the `compliance-checks` command (dry run by default) records their states and re-classifies them.
