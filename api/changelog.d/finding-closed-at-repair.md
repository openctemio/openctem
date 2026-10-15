### Fixed: closed findings get their close date from the timeline

- Migration `002185` gives closed findings that have no close date
  (`resolved_at`, read by MTTR and close-date filters) the time of the latest
  timeline entry that moved them into their current status. Findings with no
  such entry keep no date; none is invented. Idempotent.
