### Fixed: one definition of open, fixed and dispositioned findings

- Every count and job now asks "open?" and "fixed?" through one shared set
  (`pkg/domain/vulnerability/status_sets.go`), replacing about twenty
  hand-written status lists that disagreed. Open is `new`, `confirmed`,
  `in_progress`, `fix_applied`, `validated_fixed` and `not_observed`; fixed is
  `resolved`; false positives, accepted risks and duplicates are
  dispositions, never fixes.
- The daily risk snapshot no longer counts accepted, false-positive or
  duplicate findings as closed today or in MTTR, and no longer counts pentest
  drafts as open.
- Asset and asset-group finding counts, the has-findings filter, repository
  branch counters, scan severity counts and branch comparison count open
  findings only (before: accepted, false-positive and duplicate findings were
  counted). Active CVEs and the grouped view now include `fix_applied`,
  `validated_fixed` and `not_observed` findings instead of dropping them.
- Risk velocity counts a fix in the week of its close, not of its last edit;
  validation coverage counts duplicates as closed and windows on the close date.
- Migration `002150` adds `is_open_finding_status(status)`, the same set in
  SQL, rewrites the branch counter trigger with it and recounts the branches.
- A test fails when code hand-writes a new finding status list.
