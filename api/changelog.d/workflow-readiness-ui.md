### Changed: New Scan shows which workflows can run here

- The New Scan wizard asks for each workflow's readiness. The ones that can
  run come first; a workflow that is only waiting for a sensor carries a
  short note.
- A workflow that cannot run here stays visible but is off and sorted last.
  A starter card is greyed with the reason and a link to the fix (add a
  sensor, enable a tool, set up the CI pipeline). In the workflow select,
  such workflows sit under "Not available" with their reason.
- The workflow list shows the same badge ("No capable sensor online",
  "Runs in your CI pipeline", "Not available").
