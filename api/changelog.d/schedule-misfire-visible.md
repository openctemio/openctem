### Added: a missed scheduled scan run is visible on the scan and sent as an event

- When the platform was unavailable and a scheduled occurrence was more than one interval late, the scheduler skipped it and only the audit log said so. The scan now keeps the missed time and a reason (`last_missed_at`, `last_missed_reason` on the scan API), the console shows "Missed <time>: <reason>" next to Next run with a Run now button, and a `scan.schedule_missed` notification event is sent once per missed occurrence (on by default for new channels, selectable under Scan Events).
- The note clears when the next scheduled run starts. Migration 20261107031732 adds two nullable columns to `scans` (no backfill, no table rewrite).
