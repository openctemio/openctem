-- =============================================================================
-- Migration 013: Exposures and Attack Paths (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_attack_paths_updated_at ON attack_paths;
DROP TRIGGER IF EXISTS trigger_exposures_updated_at ON exposures;

DROP TABLE IF EXISTS attack_path_nodes;
DROP TABLE IF EXISTS attack_paths;
DROP TABLE IF EXISTS exposures;
