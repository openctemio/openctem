### Fixed: decisions the old taint-source check reversed are restored

- Migration `002217` restores each finding that a changed taint source moved
  from false positive or accepted back to `confirmed` (resolution
  `decision_suspended`, before migration `002173`) to its latest suspended
  decision, with a timeline entry (reason `decision_restored`) and an open
  review flag (`taint_source_changed`), in the finding's own tenant. A
  restored acceptance ends 90 days later. Idempotent.
