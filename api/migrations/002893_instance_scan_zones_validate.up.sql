-- Validates the CHECK added NOT VALID in instance_scan_zones (a scan of
-- commands without blocking writes).
ALTER TABLE commands VALIDATE CONSTRAINT chk_commands_instance_scan_zone_shared;
