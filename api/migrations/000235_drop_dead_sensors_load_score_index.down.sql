CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sensors_load_score
  ON sensors (load_score ASC) WHERE status = 'active' AND health = 'healthy';
