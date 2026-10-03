-- Remove the apex siblings 000292 added. With the code before 000292 a
-- wildcard "*.x" already covered "x", so dropping them restores the old state.
DELETE FROM scope_exclusions
WHERE created_by = 'system:migration-000292';
