### Fixed: large scans no longer lose re-sighted findings' new data

- PostgreSQL refuses a statement with more than 65535 bind parameters. The re-sighting update of
  existing findings sent 1000 rows of 75 parameters in one statement, so a rescan that saw more than
  873 existing findings again failed that step and kept only the sighting: new severity, scores,
  descriptions and locations from the scanner were dropped. Every multi-row statement now sizes its
  chunks from its parameters per row through one shared helper.
- The same limit is now respected by the asset upsert (more than 1771 assets fell back to one
  statement per asset), the CVE catalog step of ingest (more than 3855 CVEs in a report failed it),
  the exposure bulk upsert used by the certificate and DNS monitors (more than 3640 events), the
  threat-feed catalog sync (more than 7281 entries) and the batch audit insert. Id lists taken from a
  request (linking attachments, validating a scope rule's asset groups) bind one array parameter.
- When updating re-sighted findings still fails, ingest reports it as an error on the ingest result
  instead of only logging a warning.
