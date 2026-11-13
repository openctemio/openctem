-- sensor_lookup_jobs (up): lookup jobs (docs/architecture/certificate-transparency-monitoring.md).
-- The platform makes no outbound request for a passive lookup; it asks a
-- platform-owned (instance-scope) sensor, one question per row, on behalf of
-- one organization, and waits for the answer. A row lives only while its
-- question is open: the asker reads the answer and deletes the row; rows
-- older than a day are purged. The answer is bound to the row's tenant_id,
-- never to anything the sensor sends.
CREATE TABLE IF NOT EXISTS sensor_lookup_jobs (
    id          UUID        PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    capability  TEXT        NOT NULL,
    tool        TEXT        NOT NULL,
    target      TEXT        NOT NULL,
    input       JSONB       NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'open',
    -- The platform sensor that claimed the job (NULL while open).
    sensor_id   UUID        REFERENCES sensors(id) ON DELETE SET NULL,
    claimed_at  TIMESTAMPTZ,
    result      JSONB,
    error_code  TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    done_at     TIMESTAMPTZ,
    CONSTRAINT chk_sensor_lookup_jobs_capability CHECK (capability IN ('lookup.ct@1')),
    CONSTRAINT chk_sensor_lookup_jobs_status CHECK (status IN ('open', 'claimed', 'done', 'failed', 'refused')),
    CONSTRAINT chk_sensor_lookup_jobs_target CHECK (char_length(target) BETWEEN 1 AND 253 AND char_length(tool) BETWEEN 1 AND 64),
    CONSTRAINT chk_sensor_lookup_jobs_error CHECK (char_length(error_code) <= 64),
    CONSTRAINT chk_sensor_lookup_jobs_input CHECK (jsonb_typeof(input) = 'object')
);

COMMENT ON TABLE sensor_lookup_jobs IS
    'Open lookup questions (lookup.ct@1) the platform asks its instance-scope sensors for one organization; short-lived, deleted once answered.';

-- The oldest open job (claim), and an organization's jobs.
CREATE INDEX IF NOT EXISTS idx_sensor_lookup_jobs_open ON sensor_lookup_jobs (created_at) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_sensor_lookup_jobs_tenant ON sensor_lookup_jobs (tenant_id, created_at);
