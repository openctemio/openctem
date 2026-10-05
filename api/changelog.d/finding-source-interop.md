### Added: findings keep what their source knew (CTIS 1.4)

- Findings store the CTIS 1.4 interoperability members per sighting: the native identity (plugin ID / QID / rule, native severity and status, detection type, credentialed flag), every score with its system, version, source and date (CVSS v3.1 and v4.0 together, VPR and other vendor scores, EPSS, SSVC), typed vulnerability ids, the source lifecycle, solution metadata, the latest VEX statement, unmapped source fields and the normalized location (migration 001105). The finding detail returns them as `source_data`.
- A report that sends its CVE only in `vulnerability.ids`, or its check id only in `native.vuln_id`, is keyed like one that sends `cve_id` / `rule_id`; reports that already set those keep their fingerprints.
- Asset `identity_hints` (FQDN, NetBIOS name, MACs, cloud resource id) count in asset matching like the same values under their usual property names.

### Behaviour change: VEX not_affected statements (INGEST_VEX)

- A finding with a VEX `not_affected` statement and a justification is counted and audited (`ingest.vex_dry_run`) by default. With `INGEST_VEX=enforce`, an open, non-human finding of a command-bound report becomes `false_positive` with the justification as its resolution (`ingest.vex_applied`). `off` only stores the statement.

### Security: interop data is bounded and tenant-scoped

- Every interop value is bounded before storage and backed by column CHECK constraints; only the finding detail reads it; every read and write is tenant-scoped.
