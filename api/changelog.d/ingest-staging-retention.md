### Security: ingest staging no longer keeps what will never be applied

- Every segment of a protocol v2/v3 report stored its decoded payload (up to 64 MiB) in `ingest_jobs`. Only a report that completed had its payloads cleared. A report that a sensor abandoned or let expire, or that failed, kept its payloads forever. Abandoning a report freed its open-report slot at once, so a sensor could open, fill and abandon reports until the database disk was full.
- The ingest worker now runs a staging purge every 10 minutes:
  - it empties the payloads of expired and abandoned reports;
  - it deletes failed and expired reports, and finished jobs that have no report, once they are 7 days old;
  - it keeps completed reports, which coverage and CI coverage read.
- A report header (its tool and metadata, stored with the report) is limited to 64 KiB. A larger one is refused as `413 report-too-large`.
- **Upgrade note:** on its first runs on an existing database, the purge deletes old failed and expired reports and old finished jobs, 5000 rows per step every 10 minutes.
