### Security: an accepted risk without an end no longer passes the CI gate forever

- The CI gate honoured an accepted finding with no recorded end as if it never ended. One writer (a finding an accepted-risk suppression rule matches at ingest) sets the end in a separate best-effort step, so a failure there left a permanent pass. The gate now refuses an acceptance without an end (fail closed).
- The database enforces that an accepted risk always ends: an accepted finding written without an end gets the 90-day default, capped by its priority (30 days for P0 or KEV), with a timeline note for rows fixed by the migration. An end a writer sets is kept.
- Migration 20261030072206 adds the trigger and fills existing accepted findings without an end (none on a typical install).
