### Fixed: the run map was empty on the run sheet

- The run sheet read the run's step runs as `step_runs`, but the API sends
  `scan_run_steps`, so the run map never showed. The web now reads
  `scan_run_steps`, its run types are checked against the generated API
  contract, and the run sheet is tested on a fixture the API writes from its
  own response.
