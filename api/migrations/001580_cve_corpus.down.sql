DELETE FROM threat_intel_sync_status WHERE source_name = 'nvd';
DROP TABLE IF EXISTS vulnerability_affected;
DROP FUNCTION IF EXISTS vulnerability_affected_global_check();
DROP TABLE IF EXISTS cve_records;
