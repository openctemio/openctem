### Fixed: scan approval shows the mode in force, and a run's progress is one number

- Settings > Scan approval selects the mode in force. When the platform enforces a mode over the organization's choice, that mode is the selected (read-only) one and the organization's own choice is a note; it no longer shows "Off" selected under "In force: Strict".
- The scan list measures a run's progress in finished steps of the planned steps, the same figure the scan page and the run drawer show (it used to count tasks created so far). A run whose every task is still queued reads "Waiting for a sensor" instead of "Running 0%".
