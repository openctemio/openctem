### Fixed: grouped findings apply every filter of the list

- Grouping the findings list (by CVE, rule, asset and the other dimensions) now runs the list's own filter: search, priority, CISA KEV, reachable, SLA status and the asset, scan, CVE, rule, family, type, component and owner filters. Before, only severity, status, source, "assigned to me" and the lens reached the groups, and a note said the rest applied to the ungrouped list. The search box is shown in the grouped view too.
