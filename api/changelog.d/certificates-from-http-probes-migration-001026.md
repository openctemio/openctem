### Added: certificates from HTTP probes (migration 001026)

- An HTTP probe's TLS leaf certificate (`certificate` asset in a CTIS report,
  named by its SHA-256 fingerprint and linked from the service through
  `related_assets`) is stored as one certificate asset per organization and
  fingerprint, linked to the service with the new relationship type
  `serves_certificate`. Its expiry feeds the existing certificate exposures.
  A `related_assets` link becomes an edge only for a known type pair, only
  when both assets were stored by the same ingest, and only when the report
  may change the source asset; at most 100 links per asset are read.
- Certificate text (subject, issuer, serial, SANs, algorithms) is capped and
  stripped of control characters on every ingest path, like finding text.
