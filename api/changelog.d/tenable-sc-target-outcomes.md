### Changed: a Tenable.sc scan's unfinished targets are recorded on its run

- When a `connector_scan` result carries per-target outcomes (sensor with the Tenable.sc tracking change), the targets it left unfinished end the step `partial` with "N target(s) not finished" and are recorded on the run's unfinished targets, so the next scheduled run plans them first and coverage never reads them as covered. Targets are read against the command's own targets; a sensor cannot add one. Results without outcomes (older sensors) behave as before.
