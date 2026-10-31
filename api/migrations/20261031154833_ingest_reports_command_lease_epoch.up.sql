-- The lease epoch of the command a v2 report was bound to, recorded when the
-- report was accepted (docs/architecture/sensor-platform-workflow.md, "Late
-- results"). The ingest worker processes a queued report only while the
-- sensor still holds the command under that epoch: a report of a run the
-- platform took back and handed out again is dropped. NULL for a report with
-- no command and for rows written before this column (holder check only).
-- Adding a nullable column without a default is a catalog-only change.
ALTER TABLE ingest_reports ADD COLUMN IF NOT EXISTS command_lease_epoch integer;
