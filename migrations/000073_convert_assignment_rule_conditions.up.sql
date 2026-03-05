-- Convert assignment_rules.conditions from array-of-objects format to flat-object format.
--
-- Old format (array): [{"field": "severity", "value": "critical", "operator": "equals"}, ...]
-- New format (object): {"finding_severity": ["critical"], "asset_type": ["host", "ip"]}
--
-- Conversion rules:
--   field "severity"   → key "finding_severity"
--   field "asset_type"  → key "asset_type"
--   field "source"      → key "finding_source"
--   field "type"        → key "finding_type"
--   field "tags"        → key "asset_tags"
--   value (string)      → wrapped in array
--   value (array)       → kept as array

UPDATE assignment_rules
SET conditions = (
    SELECT COALESCE(
        jsonb_object_agg(
            CASE elem->>'field'
                WHEN 'severity' THEN 'finding_severity'
                WHEN 'source' THEN 'finding_source'
                WHEN 'type' THEN 'finding_type'
                WHEN 'tags' THEN 'asset_tags'
                ELSE elem->>'field'
            END,
            CASE jsonb_typeof(elem->'value')
                WHEN 'array' THEN elem->'value'
                ELSE jsonb_build_array(elem->'value')
            END
        ),
        '{}'::jsonb
    )
    FROM jsonb_array_elements(conditions) AS elem
)
WHERE jsonb_typeof(conditions) = 'array' AND jsonb_array_length(conditions) > 0;

-- Also convert empty arrays to empty objects
UPDATE assignment_rules
SET conditions = '{}'::jsonb
WHERE jsonb_typeof(conditions) = 'array' AND jsonb_array_length(conditions) = 0;
