-- Task logs keep every attempt of a command (docs/rfcs/RFC-029-sensor-
-- protocol-v2-and-sdk-stability.md §4.4.1). A command that is re-queued
-- (lease expiry, sensor restart, release) and claimed again starts a new
-- lease epoch, and its sensor numbers that attempt's log batches from seq 0
-- again. Batches were keyed by (command_id, seq), so the new attempt's
-- batches were taken for replays of the old one and silently dropped. They
-- are now keyed by (command_id, lease_epoch, seq); lease_epoch is the
-- commands.lease_epoch the batch was written under, read by the platform
-- (never sent by the sensor).
--
-- Live impact: command_logs holds at most 14 days of batches. Adding the
-- column with a constant default is a catalog-only change; the backfill
-- rewrites the rows of that window once, and the primary key is rebuilt
-- under a short exclusive lock. Existing batches get the current lease
-- epoch of their command (the attempt that most likely wrote them).

ALTER TABLE command_logs ADD COLUMN lease_epoch integer NOT NULL DEFAULT 0;

UPDATE command_logs l
SET lease_epoch = c.lease_epoch
FROM commands c
WHERE c.id = l.command_id AND c.lease_epoch <> 0;

ALTER TABLE command_logs ADD CONSTRAINT chk_command_logs_lease_epoch CHECK (lease_epoch >= 0);

ALTER TABLE command_logs DROP CONSTRAINT command_logs_pkey;
ALTER TABLE command_logs ADD CONSTRAINT command_logs_pkey PRIMARY KEY (command_id, lease_epoch, seq);

COMMENT ON COLUMN command_logs.lease_epoch IS
    'The commands.lease_epoch (claim attempt) the batch was written under; seq restarts at 0 in each attempt.';
