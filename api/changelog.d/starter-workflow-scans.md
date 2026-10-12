### Fixed: scans on a starter workflow can be created and run

- The New scan wizard offers the starter (system) workflows, but creating
  a scan on one failed with "Scan not found": the scan's workflow was looked
  up only among the organization's own workflows. Starter workflows are now
  usable, read-only, by every organization when a scan is created, edited,
  quick-started, run on schedule or pinned to a version; another
  organization's private workflow stays out of reach, and changing a starter
  workflow still needs "Duplicate to edit".
- A missing workflow is now answered 404 "Scan workflow not found" (code
  `SCAN_WORKFLOW_NOT_FOUND`) instead of "Scan not found"; a disabled one is
  refused with a 400 that names it.
