### Added: a nightly load test of the ingest pipeline

- The `Ingest load` workflow (nightly and manual) migrates a fresh Postgres and runs `TestIngestLoad`: 50 concurrent CI uploads of 1,000 findings each through the real accept path, queue and workers; an urgent report behind 500 bulk jobs (applied within 15 s); 20 uploads of the same findings to one repository (no failed upload, no lost sighting). A missed target fails the job; the results are in the run summary.
