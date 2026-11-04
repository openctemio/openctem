### Fixed: Run now on a workflow with steps that wait for a tool answered "Scan not found"

- A workflow scan on the Standard recon, Web or Deep recon system workflow could not run, by hand or on its
  schedule: their optional steps on a capability no installed tool implements yet (screenshots, service
  detection) made the tool lookup answer "not found", which the trigger did not treat as "no tool" and the
  API answered as "Scan not found". Those steps are now skipped with the reason, as the workflow preview
  already showed, and the scan runs.
- A trigger whose scan was found but whose workflow is gone now answers `PIPELINE_NOT_FOUND`, and any other
  missing reference `SCAN_DEPENDENCY_MISSING` (both recorded as a blocked run), instead of "Scan not found".
  A scheduled run that hit this no longer fails without a trace on the scan.

### Security: a workflow scan runs only its organization's workflow or a system template

- The trigger loads the scan's workflow scoped to the scan's organization, or as a shared system template,
  before any gate reads its steps. A scan row naming another organization's private workflow is refused
  with `PIPELINE_NOT_FOUND` and nothing is dispatched; before, the trigger read that workflow unscoped.
