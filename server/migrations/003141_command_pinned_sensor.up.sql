-- A command addressed to one sensor on purpose (config_update, a connector
-- scan pinned to one runner, ...) records that sensor here when it is
-- claimed, because sensor_id then also names the holder. A lease that
-- expires puts the command back to pending addressed to this sensor again
-- instead of leaving it open to every sensor. NULL: not addressed.
-- Nullable column without a default: no table rewrite.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS pinned_sensor_id UUID;
