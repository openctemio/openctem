-- Intentional no-op. The up migration corrects data that was wrong (an asset
-- typed against its own name); restoring the wrong type would re-break it.
-- The old type and sub-type of every changed row are in audit_logs
-- (action 'asset.type_corrected', metadata.old_type / old_sub_type).
SELECT 1;
