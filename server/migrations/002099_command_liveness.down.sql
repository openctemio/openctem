ALTER TABLE commands DROP COLUMN IF EXISTS stop_requested_at;
ALTER TABLE commands DROP COLUMN IF EXISTS progress_cpu_mark;
ALTER TABLE commands DROP COLUMN IF EXISTS progress_cpu_ms;
ALTER TABLE commands DROP COLUMN IF EXISTS progress_output_bytes;
ALTER TABLE commands DROP COLUMN IF EXISTS progress_records;
