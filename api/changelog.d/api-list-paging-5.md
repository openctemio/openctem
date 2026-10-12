### Changed: the remaining page / per_page lists share one page parser

- Twenty-six more list handlers read `page` and `per_page` with the shared
  parser: API keys, asset groups, relationships and types, branches,
  capabilities, CI admin, coverage and pipelines, commands, components,
  EASM review, exposures, finding sources, the sensor fleet, notifications,
  relationship suggestions, scanner templates, scan profiles, scope, sensors
  and sensor results, tools and tool categories, findings and automations,
  and the audit log. A `page` of 0 or a non-numeric `page` / `per_page` is
  refused with 400 instead of being read as the first page; `per_page` is
  capped at 100 (the audit log had no cap; lists with a lower cap keep it).
