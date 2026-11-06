-- gap_beats counted every heartbeat that had a previous one, so it always
-- equalled beats minus the first one and said nothing about gaps. It now
-- counts late heartbeats (a gap above 1.5 intervals); the old meaning moves
-- to prev_beats, the divisor of the average gap.
--
-- Live impact: one NOT NULL column with a constant default (catalog-only),
-- then an update of the 48 hours of buckets (at most 192 rows per sensor).
ALTER TABLE sensor_heartbeat_history ADD COLUMN prev_beats integer NOT NULL DEFAULT 0;
UPDATE sensor_heartbeat_history SET prev_beats = gap_beats, gap_beats = 0;
ALTER TABLE sensor_heartbeat_history ADD CONSTRAINT sensor_heartbeat_history_prev_beats CHECK (prev_beats >= 0 AND prev_beats <= beats);
