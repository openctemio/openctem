### Behaviour change: New scan never refuses a scan for a missing tool or sensor (redesign branch)

- A workflow step that no tool or sensor here runs is read as skipped, required or optional, as a run treats it: the
  Review step warns "N steps are skipped; the other steps run" instead of refusing Create, and the workflow preview
  shows the step as skipped. When no step can run, the scan is still saved and the notice says its start is refused
  until a tool or sensor for its steps is available.
- A workflow whose readiness is blocked is offered under "Runs in part" with the steps it skips; a CI-only workflow
  stays off (it runs in a CI pipeline).
- A scanner that no sensor can run now is offered with the reason; once chosen, the field says the scan is saved and
  its start is refused until such a sensor is online.
- No request changes; the server already saves such scans and skips such steps at run time.
- Docs: none (the console says what is skipped; scan stages are described in server/docs/architecture/scan-stages.md)
