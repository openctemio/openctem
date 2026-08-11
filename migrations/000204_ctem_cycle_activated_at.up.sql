-- Migration 000204: CTEM cycle activation timestamp (RFC-005 cycle metrics)
--
-- The cycle-metrics layer computes each metric over the cycle's active
-- window [activated_at, closed_at]. ctem_cycles recorded closed_at but
-- never the activation moment, so add it. Additive + reversible; NULL
-- for cycles activated before this migration (metric computation falls
-- back to created_at for those).
ALTER TABLE ctem_cycles ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
