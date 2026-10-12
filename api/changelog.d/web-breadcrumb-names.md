### Fixed: breadcrumbs name records instead of showing their ids

- The header breadcrumb showed a shortened record id on most detail pages ("dcdc3001...") and the full id when the record was in the middle of the path (a template edit page). Cycle, asset group, scan, scan workflow, pentest campaign, remediation campaign and pentest template pages now name their record, and before the name loads the crumb says what the record is ("Scan", "Template"), never the id.
