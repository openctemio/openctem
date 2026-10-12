### Changed: the Findings overview cards are page-level and load with one stats request

- The cards above the findings list (Total, Open, Critical open, High open,
  Overdue SLA, In CISA KEV, Awaiting verification) now count every finding the
  caller may see, whatever the state tab, search or filters. Total equals the
  All tab and Open the Open tab. Filter-aware numbers stay in the tab counts and
  the result bar. Each card applies the filter it counts and explains itself in
  a tooltip.
- `GET /findings/stats` adds `open_by_severity` and `awaiting_verification`.
  `kev_open`, `epss_high_open` and `sla_breached` now use the Open tab's
  predicate, so pentest drafts and findings in review are no longer counted.
- The page loads one stats response instead of two, switching tabs sends no
  stats request, the grouped and verification views no longer load the flat
  list, and the saved-views menu loads its list and your groups only when used.

### Fixed: "Awaiting verification" on the Findings page always showed 0

- It read a status count the stats response never carried; it now reads
  `awaiting_verification`.
