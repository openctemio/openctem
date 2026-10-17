### Added: ticket field mapping editor in the console

- Settings → Integrations → Ticket field mapping lists the mapping profiles
  and creates one per Jira project and issue type (findings or remediation
  tasks), from a preset.
- The editor connects OpenCTEM attributes to Jira fields (pick or drag), with
  direction, transform (value map against the field's allowed values, user,
  date, number, labels, join), sync mode and conflict winner per row, a
  sample render for templates, and the problems found against the live
  project.
- The Status tab draws the project's workflow, maps OpenCTEM states to
  workflow statuses (with resolution) and workflow statuses to intents
  (requests marked as needing approval), and simulates both directions.
- Preview of the issue a finding or task would create and of what an
  existing issue would change; version history with diff and rollback;
  import and export; dry run; a check for Jira changes. English and
  Vietnamese.
