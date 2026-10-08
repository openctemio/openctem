### Behaviour change: one finding status set for every source

- Pentest findings use the statuses every finding uses: `remediation` is now `in_progress`, `retest` is `fix_applied`, `verified` is `resolved` (how it was closed is `resolution_method = retest_verified`), `accepted_risk` is `accepted`. `draft` and `in_review` stay as the pentest pre-publication states. The pentest lifecycle is `vulnerability.PentestStatusTransitions` (one map for the legacy and unified paths).
- The API refuses the retired values (and `open`) with a 400 in status changes, pentest finding updates and list filters; nothing is mapped silently. The OpenAPI status enums list the canonical set.
- Pentest campaign stats are keyed `in_progress_count`, `fix_applied_count`, `resolved_count`, `false_positive_count`, `accepted_count` (were `remediation_count`, `retest_count`, `verified_count`, `false_positives`, `accepted_risks`).
- Finding stats `by_status` gains `fix_applied`, `validated_fixed` and `not_observed`; `open_count` is new + confirmed + in_progress (+ draft, in_review).
- The web console has one status registry (labels in English and Vietnamese, category, color); the findings filter groups statuses by category, each status once.
- Migration `001378` maps stored alias values (and `open`) in findings, pentest findings, approvals and retests, and adds a CHECK on the canonical set to `findings.status` and `pentest_findings.status`. It is idempotent.
- **Upgrade note:** API clients that send `remediation`, `retest`, `verified`, `accepted_risk` or `open` as a finding status must send the canonical status.
