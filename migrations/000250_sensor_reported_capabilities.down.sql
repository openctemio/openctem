ALTER TABLE sensors
    DROP COLUMN IF EXISTS effective_max_jobs,
    DROP COLUMN IF EXISTS effective_capabilities,
    DROP COLUMN IF EXISTS effective_tools,
    DROP COLUMN IF EXISTS reported_at,
    DROP COLUMN IF EXISTS reported_arch,
    DROP COLUMN IF EXISTS reported_os,
    DROP COLUMN IF EXISTS reported_max_jobs,
    DROP COLUMN IF EXISTS reported_capabilities,
    DROP COLUMN IF EXISTS reported_tool_names,
    DROP COLUMN IF EXISTS reported_tools;

DROP FUNCTION IF EXISTS sensor_effective_list(text[], text[]);
