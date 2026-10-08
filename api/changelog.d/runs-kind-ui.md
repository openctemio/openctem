### Added: retests on the Runs page

- Scans › Runs filters by kind (scans, quick scans, retests); system runs stay
  hidden. A retest run is named "Retest" and links to its finding. The CSV
  export has a Kind column.
- A finding's retest has a "View run" link that opens the run (its tasks and
  their logs) at `/scans/runs?run=<id>`. The link is shown only to users with
  scans:read. The run page leaves out stages and dispatch for runs that execute
  no scan workflow.
