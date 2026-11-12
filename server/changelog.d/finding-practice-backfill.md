### Added: `finding-practice` command to set the practice of existing findings

- A new operator command in the API image (`finding-practice`, a link to the server binary) derives the practice of
  findings stored before practices existed, and of open findings whose inputs changed, with the same rules as ingest.
- A dry run is the default: a read-only connection and a report of aggregates per tenant (findings per practice
  before and after, moves between practices with open and closed counts, rows to change). `-apply` writes only the
  differences in pages, queues a dashboard refresh for the moved assets, and can be rerun safely.
- **Upgrade note:** run `finding-practice` (dry run) after upgrading, review the report, then `finding-practice -apply`.
