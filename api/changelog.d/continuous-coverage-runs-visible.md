### Fixed: continuous coverage runs are visible under Scans

- Scans > Runs labels the runs of scans the platform manages (continuous coverage, enrichment) with a badge, and the kind filter gains "Continuous coverage". "Scans" leaves those runs out, "All kinds" lists everything. `GET /api/v1/scan-runs` takes `origin=user|system` and each row carries `managed_by`.
- Scans lists the managed scans in a read-only section, "Managed by continuous coverage", with links to the coverage settings and to their runs.
- The "new internet-facing assets discovered" notification links to the scan run that found the assets when one run found them all.
- The Runs empty state no longer says "No scan runs yet" while the counters show runs.
