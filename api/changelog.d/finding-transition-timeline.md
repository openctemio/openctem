### Fixed: every automatic status move is on the finding's timeline, in the same transaction

- About fifteen platform moves wrote no timeline entry, or wrote it after the
  move in a separate write: template drift, feature-branch expiry, CI
  pipeline stale and retired, VEX in scan reports and VEX documents, the
  software vulnerability matcher, correlation link and release, taint-source
  suspension, suppression re-link, validation verdicts, the IOC correlator,
  workflow `update_status`, auto-assign to owners, bulk verify / reject by
  filter, coverage auto-resolve and scan re-detection.
- Each now writes one entry per moved finding in the same transaction as the
  move, with the old and new status, the previous resolution, a reason code,
  the actor and the evidence behind it (scanner, scan, pipeline, rule,
  statement). Migration `002180` adds the trigger
  `trg_findings_record_transition` that writes it for a writer that names
  itself for its transaction.
- A workflow's status change is recorded with the actor `workflow:<id>`;
  before, its entry failed on an invalid actor id.
