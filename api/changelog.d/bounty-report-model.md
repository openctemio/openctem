### Added: one finding per bug-bounty report

- Findings with source `bug_bounty` can carry a typed report object (`metadata.bounty_report`: intake, report id, researcher handle, submitted time, reported severity, channel state, CWE, endpoint path and parameter, an https back-link, reward and disclosure as data), validated with length caps, an https-only link without user info, ISO 4217 currencies and no control or bidirectional formatting characters in single-line fields (RFC-121).
- Migration `003275_findings_bounty_report_ref_unique` adds a partial unique index so a tenant holds at most one `bug_bounty` finding per (intake, report id); a second one is a conflict.
- **Upgrade note:** the index is built with `CREATE INDEX CONCURRENTLY` (no write lock on `findings`); no existing finding carries a report object, so the build cannot fail on duplicates.
