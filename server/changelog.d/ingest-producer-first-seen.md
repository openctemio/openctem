### Fixed: a finding is first detected when its scanner first saw it

- Ingest ignored a finding's CTIS `first_seen_at`, so every finding of a first import looked detected today. A
  finding is now first detected at the producer's first-seen time, bounded: a time in the future counts as now, a
  time before 2000-01-01 is ignored. First detection only moves earlier, also on a re-sighting of an existing
  finding, never later. The SLA clock starts at the first detection, as before.
- The producer's claim is kept as producer-supplied (new column `findings.first_detected_reported_at`, migration
  `20261127112618_findings_first_detected_reported_at`, nullable, no rewrite); the platform's own receipt time
  stays in `created_at`.
- Docs: server/docs/architecture/ctis-receiver.md
