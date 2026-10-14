### Fixed: a DAST finding re-sighted by a newer sensor is no longer a new finding

- A sensor that reports the HTTP method in the CTIS web location (instead of a `method` or `request` property) made every re-sighted DAST finding a new one, and its triage stayed on the old one. Ingest now reads the method from the web location too, and a missing method counts as GET, so a field a producer stops sending never forks a finding again. A fuzzed parameter in the web location now counts as well.
- A fixed-path detection template that matches several of its own request paths on one target (for example `/wp-json/wp/v2/users` and `/?rest_route=/wp/v2/users`) is one finding, keyed on the target the producer names in `source_extra.target`. Endpoints given as targets and fuzzed parameters keep one finding each. A finding keyed on its matched URL before is re-keyed on its next sighting, keeping its triage.

### Added: a one-time DAST identity repair

- `refingerprint -dast-repair [-fold-dast-rules r1,r2] [-apply]` folds DAST findings that are one issue under the current recipe. Dry run by default; the earliest-created finding survives with its triage; the others become audited tombstones; idempotent.
