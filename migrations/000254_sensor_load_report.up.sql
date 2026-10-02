-- Sensor load report (RFC-030 §5.8): what the sensor measures about itself on
-- each heartbeat, computed by the SDK (cgroup-aware CPU and memory, load
-- average, free disk, dynamic job slots, per-tool observed cost, local work
-- queue). Untrusted: the API clamps every value before it is stored, and the
-- report can only LOWER what dispatch hands the sensor (free slots never
-- exceed effective_max_jobs minus the commands the sensor holds).
--
-- Additive and nullable. NULL: never reported (an SDK from before the
-- report), the server-side count of the sensor's commands applies alone.
ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS reported_resources jsonb,
    ADD COLUMN IF NOT EXISTS reported_capacity jsonb,
    ADD COLUMN IF NOT EXISTS reported_queue jsonb,
    ADD COLUMN IF NOT EXISTS load_reported_at timestamptz;

COMMENT ON COLUMN sensors.reported_resources IS 'Resources the sensor last reported: {cpu_cores, cpu_used_pct, mem_total_bytes, mem_available_bytes, load1, disk_free_bytes}. Untrusted, clamped at ingest. Display and selection input only.';
COMMENT ON COLUMN sensors.reported_capacity IS 'Job capacity the sensor last reported: {slots_total, slots_free, active_jobs, per_tool: {tool: {est_cpu_s, est_mem_bytes, throughput_targets_per_min}}}. Untrusted, clamped; can only lower dispatch capacity.';
COMMENT ON COLUMN sensors.reported_queue IS 'The sensor''s local work queue as last reported: {claimed, running, queued_local, oldest_age_seconds}. Display only.';
COMMENT ON COLUMN sensors.load_reported_at IS 'When a load report (resources, capacity or queue) was last written; a report older than 3 minutes is not used for dispatch.';
