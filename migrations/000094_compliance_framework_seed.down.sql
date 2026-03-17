-- Remove all seeded controls and frameworks (CASCADE handles controls)
DELETE FROM compliance_controls WHERE framework_id IN (
    SELECT id FROM compliance_frameworks WHERE is_system = TRUE
);
DELETE FROM compliance_frameworks WHERE is_system = TRUE;
