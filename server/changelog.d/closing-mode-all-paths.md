### Security: the organization's closing mode governs every automatic close

- A clean full default-branch scan, a full-coverage upload (`coverage=full`) and a software version change no longer close findings around the organization's closing mode. Each now goes through the same rule as coverage auto-resolve: `off` keeps the finding open, `review` records a Ready to close proposal (methods `ci_default_branch`, `covered_scan`, `source_reported`), `auto` closes per the tier rule.
- The daily evidence limit holds under concurrent writes: recorded request/response evidence is counted inside the insert transaction under a per-tenant lock.

### Behaviour change: those closes become proposals in review mode

- Organizations in `review` (including every organization created before the setting existed) get Ready to close proposals for those closes instead of automatic ones. A held run (blinding guard) proposes its findings unless the mode is `off`. A full-coverage upload that only proposed carries the receipt note `proposed`. Confirming a `ci_default_branch` proposal records verification `covered_scan`.
