### Behaviour change: a verified first-party tool that reports an undeclared type is ingested, not held

- A report from a built-in tool (origin builtin) on a trusted sensor, whose descriptor was sent by the sensor and matches its digest, no longer has its assets and findings parked in the review queue because its descriptor lags its importer. What the platform catalog allows for the tool and the command's targets cover is ingested and flagged: a `contract_mismatch` entry on the ingest receipt, the audit event `sensor_result.contract_mismatch`, and one notice to the platform administrators per tool, type and version a day.
- Unchanged: third-party, unsigned or untrusted tools and descriptors, unverified sensors, assets outside the command's targets, dependencies, endpoints and the quarantine caps still hold the report for review.
- No migration.
