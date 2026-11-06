-- Back to one log per command keyed by (command_id, seq). Lossy: where
-- several attempts wrote the same seq, only the earliest attempt's batch is
-- kept (what the old key kept).

DELETE FROM command_logs l
USING command_logs e
WHERE e.command_id = l.command_id AND e.seq = l.seq AND e.lease_epoch < l.lease_epoch;

ALTER TABLE command_logs DROP CONSTRAINT command_logs_pkey;
ALTER TABLE command_logs ADD CONSTRAINT command_logs_pkey PRIMARY KEY (command_id, seq);
ALTER TABLE command_logs DROP CONSTRAINT chk_command_logs_lease_epoch;
ALTER TABLE command_logs DROP COLUMN lease_epoch;
