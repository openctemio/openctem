ALTER TABLE sensor_heartbeat_history DROP CONSTRAINT IF EXISTS sensor_heartbeat_history_prev_beats;
UPDATE sensor_heartbeat_history SET gap_beats = prev_beats;
ALTER TABLE sensor_heartbeat_history DROP COLUMN IF EXISTS prev_beats;
