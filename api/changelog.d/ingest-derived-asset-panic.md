### Fixed: a sensor report with an endpoint no longer crashes the API

- Ingest appends the web origin of an endpoint as a derived asset; when one was not stored, the per-asset outcome indexed past the producer's asset list and panicked, killing the API, and the queue handed the same job out again after every restart. Derived assets are now kept out of the producer's counts and item errors, and a panic in one ingest job marks that job dead (apply_failed) instead of stopping the process.
