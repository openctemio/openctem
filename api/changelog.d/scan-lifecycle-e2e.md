### Added: end-to-end test of a scan's life in the console

- A Playwright spec creates a single-scanner and a workflow scan in the New Scan wizard, edits each (name, targets, max duration) from its page, runs it and opens the run, so a broken Edit can no longer pass unnoticed. The e2e seed's sensor gets a tier ceiling that lets active workflow steps be saved.
