-- Finding source records: what each source reported for a finding
-- (docs/architecture/finding-source-records.md).
--
-- One finding, many sources. A source is the channel (a scan run, a sensor
-- task outside a run, an unsolicited sensor report, an upload, a CI run, a
-- connector, the platform), the tenant's sensor, the sender (a CI repository
-- or connector source name) and the tool: the sighting key without the scan
-- definition. Each row keeps that source's latest values of every field the
-- finding row merges (text, rating, type details, native identity, scores,
-- vulnerability ids, unmapped source fields), so a second source never
-- overwrites what the first one said. At most 64 sources per finding (the
-- writer enforces it); every value is capped by the writer and by the CHECKs
-- below. Rows live as long as their finding.
--
-- The finding key is composite (tenant_id, finding_id) -> findings
-- (tenant_id, id): a row can never point at another tenant's finding.
--
-- Live impact: one new, empty table and its key. No backfill here: existing
-- findings get records from the explicit finding-source-backfill command (a
-- dry run by default).

CREATE TABLE IF NOT EXISTS finding_source_records (
    tenant_id         uuid          NOT NULL,
    finding_id        uuid          NOT NULL,
    channel           varchar(16)   NOT NULL,
    sensor_id         uuid,
    sender            varchar(128)  NOT NULL DEFAULT '',
    tool              varchar(100)  NOT NULL DEFAULT '',
    tool_version      varchar(100),
    first_seen_at     timestamptz   NOT NULL,
    last_seen_at      timestamptz   NOT NULL,
    title             text,
    description       text,
    snippet           text,
    recommendation    text,
    message           text,
    severity          varchar(16),
    cvss_score        numeric(3, 1),
    cvss_vector       varchar(255),
    type_details      jsonb,
    native_vuln_id    varchar(256),
    native_scheme     varchar(64),
    source_meta       jsonb,
    scores            jsonb,
    vulnerability_ids jsonb,
    source_extra      jsonb,
    location_key      varchar(512),
    clipped         boolean       NOT NULL DEFAULT false,
    backfilled        boolean       NOT NULL DEFAULT false,
    updated_at        timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT ux_finding_source_records_source UNIQUE NULLS NOT DISTINCT
        (tenant_id, finding_id, channel, sensor_id, sender, tool),
    CONSTRAINT fk_finding_source_records_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_source_records_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_source_records_channel
        CHECK (channel IN ('scan', 'task', 'sensor', 'upload', 'ci', 'connector', 'platform', 'unknown')),
    CONSTRAINT chk_finding_source_records_unknown CHECK (channel <> 'unknown' OR backfilled),
    CONSTRAINT chk_finding_source_records_seen CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT chk_finding_source_records_text CHECK (
        char_length(title) <= 1024 AND char_length(description) <= 32768 AND char_length(snippet) <= 10240
        AND char_length(recommendation) <= 16384 AND char_length(message) <= 4096),
    CONSTRAINT chk_finding_source_records_json CHECK (
        octet_length(type_details::text) <= 16384 AND octet_length(source_meta::text) <= 131072
        AND octet_length(scores::text) <= 131072 AND octet_length(vulnerability_ids::text) <= 131072
        AND octet_length(source_extra::text) <= 131072)
);

COMMENT ON TABLE finding_source_records IS
    'What each source reported for a finding: one row per finding and source (channel, the tenant''s sensor, sender, tool) with that source''s latest title, text, severity, type details, native identity, scores, vulnerability ids and unmapped fields, and its first and last seen. At most 64 sources per finding; rows live with their finding.';
COMMENT ON COLUMN finding_source_records.sensor_id IS
    'The tenant''s own sensor that reported it; NULL for a shared platform sensor (sender is then platform) and for non-sensor channels. No FK: the record outlives a deleted sensor.';
COMMENT ON COLUMN finding_source_records.sender IS
    'The CI repository or connector source name for those channels; platform for a shared sensor; empty otherwise. Untrusted text, clipped.';
COMMENT ON COLUMN finding_source_records.clipped IS
    'true when a value of this source was cut to its cap before storage.';
COMMENT ON COLUMN finding_source_records.backfilled IS
    'true when the row was derived by finding-source-backfill from the finding row as it was before records existed; its values may mix earlier sources.';

-- Row-level security in shadow mode, like the other tenant tables.
DROP POLICY IF EXISTS finding_source_records_tenant_isolation ON finding_source_records;
CREATE POLICY finding_source_records_tenant_isolation ON finding_source_records
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
