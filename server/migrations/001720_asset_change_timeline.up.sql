-- Asset change timeline (RFC-069 §11): one event each time the value an
-- asset shows for a reconciled attribute changes, or its deciding source
-- changes. Re-sightings of the same value write nothing.

-- Which scan task, CI run or feed sequence an observation came from, and
-- whether it is the value the asset currently shows.
ALTER TABLE asset_attribute_sources
    ADD COLUMN source_run VARCHAR(100) NOT NULL DEFAULT '',
    ADD COLUMN winner     BOOLEAN      NOT NULL DEFAULT false;
COMMENT ON COLUMN asset_attribute_sources.source_run IS
    'RFC-069: scan task (command), CI run, import or feed sequence the observation came from';
COMMENT ON COLUMN asset_attribute_sources.winner IS
    'RFC-069: this source decides the value the asset shows (set by the resolver)';

-- Append-only apart from flap coalescing (the newest event of an attribute
-- is updated when the value flips back within a short window) and retention
-- (rows past the retention window are deleted). Partitioned by month on
-- "at". The server runs no DDL (least-privilege role): migrations create the
-- months ahead; a row outside them lands in the default partition.
CREATE TABLE asset_change_events (
    id           UUID         NOT NULL,
    tenant_id    UUID         NOT NULL,
    asset_id     UUID         NOT NULL,
    at           TIMESTAMPTZ  NOT NULL,
    attribute    VARCHAR(40)  NOT NULL,
    old_value    VARCHAR(500) NOT NULL DEFAULT '',
    new_value    VARCHAR(500) NOT NULL DEFAULT '',
    added        TEXT[],
    removed      TEXT[],
    source_kind  VARCHAR(20)  NOT NULL,
    source_name  VARCHAR(100) NOT NULL DEFAULT '',
    source_run   VARCHAR(100) NOT NULL DEFAULT '',
    actor_id     UUID,
    reason       VARCHAR(30)  NOT NULL,
    flap_count   INTEGER      NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_change_events PRIMARY KEY (tenant_id, at, id),
    CONSTRAINT fk_asset_change_events_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_change_events_reason CHECK (reason IN (
        'newer_observation', 'manual_lock', 'lock_released', 'ttl_expiry', 'policy_change', 'source_removed')),
    CONSTRAINT chk_asset_change_events_flaps CHECK (flap_count >= 1),
    CONSTRAINT chk_asset_change_events_set_size CHECK (
        COALESCE(cardinality(added), 0) <= 200 AND COALESCE(cardinality(removed), 0) <= 200)
) PARTITION BY RANGE (at);
COMMENT ON TABLE asset_change_events IS
    'RFC-069: asset change timeline. One row per change of a resolved attribute value or of its deciding source; monthly partitions; retention drops old months.';

CREATE INDEX idx_asset_change_events_asset ON asset_change_events (tenant_id, asset_id, at DESC, id DESC);
CREATE INDEX idx_asset_change_events_tenant ON asset_change_events (tenant_id, at DESC, id DESC);

-- Rows outside every monthly partition (an import that reports old
-- timestamps) land here; retention deletes them by date.
CREATE TABLE asset_change_events_default PARTITION OF asset_change_events DEFAULT;

-- Creates the monthly partitions from the month of "from" for "months"
-- months; existing ones are kept. Migrations call it (the migrator owns the
-- schema); a later migration extends the months before these run out.
CREATE OR REPLACE FUNCTION asset_change_events_ensure_partitions(from_month DATE, months INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE
    m       DATE := date_trunc('month', from_month)::date;
    created INTEGER := 0;
    part    TEXT;
BEGIN
    FOR i IN 0 .. GREATEST(months, 1) - 1 LOOP
        part := 'asset_change_events_' || to_char(m, 'YYYY_MM');
        IF to_regclass(part) IS NULL THEN
            EXECUTE format('CREATE TABLE %I PARTITION OF asset_change_events FOR VALUES FROM (%L) TO (%L)',
                           part, m, (m + interval '1 month')::date);
            created := created + 1;
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
    RETURN created;
END;
$$;

-- Last month through the next two years.
SELECT asset_change_events_ensure_partitions((now() - interval '1 month')::date, 27);
