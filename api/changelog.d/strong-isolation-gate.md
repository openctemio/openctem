### Added: jobs of a tool that needs strong isolation wait for a sensor that proved it

- A tool whose manifest says `isolation: strong` gets `required_features: ["isolation.strong@1"]` on its jobs. Only a sensor that itself reported the capability (it ran a confined task on a strong isolation backend at start-up) is offered them; others leave them queued with the placement reason `strong_isolation_missing`, and the run page explains it in English and Vietnamese. A job is never run on the process sandbox instead and never refused when it is queued.
- No bundled tool needs strong isolation yet and no strong backend ships yet, so nothing changes for existing scans.
