### Fixed: the SLA status follows every status change, with one warning definition

- `sla_status` is now recomputed on every status or deadline change, whatever
  path makes it (trigger `trg_findings_recompute_sla_status`, migration
  `002181`): false positives, accepted risks and duplicates are
  `not_applicable`; a resolved finding is `on_track` when fixed by the
  deadline and `exceeded` otherwise; an open finding past its deadline is
  `overdue`. Before, it was only computed when a deadline was set, so closed
  findings kept `overdue` and dispositions showed `exceeded` in lists, filters
  and exports.
- One warning definition: the SLA escalation job's policy threshold, now
  measured from the reopen for a regression's restarted deadline (it flipped
  to warning at once). The domain's own 24-hour warning is removed.
- The migration recomputes stale values in place.
