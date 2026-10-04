-- RFC-043 §6 (item 10): versioned finding identity.
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
--
-- findings.fingerprint stays the finding's current key (unique per tenant).
-- finding_fingerprints holds EVERY key a finding has had: its current one and
-- the ones it gave up (an older recipe version, the key it had on an asset
-- that was merged away, the key of a duplicate folded into it). Ingest looks
-- an incoming key up here, so a recipe change or a merge re-keys a finding
-- without losing it, its triage or its tickets.
--
-- Tenant isolation is enforced by the schema: an alias references its finding
-- by (id, tenant_id), so it can only name a finding of its own tenant.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS fingerprint_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS identity_key JSONB;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_fingerprint_version;
ALTER TABLE findings ADD CONSTRAINT chk_findings_fingerprint_version CHECK (fingerprint_version >= 1);

COMMENT ON COLUMN findings.fingerprint_version IS
    'Version of the identity recipe that produced fingerprint (RFC-043 §6).';
COMMENT ON COLUMN findings.identity_key IS
    'Canonical identity tuple the fingerprint was hashed from, so the key can be recomputed without the original report (RFC-043 §4.1.3).';

CREATE TABLE IF NOT EXISTS finding_fingerprints (
    tenant_id   UUID NOT NULL,
    fingerprint VARCHAR(512) NOT NULL,
    finding_id  UUID NOT NULL,
    version     SMALLINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, fingerprint),
    CONSTRAINT fk_finding_fingerprints_finding FOREIGN KEY (finding_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_fingerprints_version CHECK (version >= 1),
    -- A tombstone gives up its key ('dup:<id>'); that placeholder is never an alias.
    CONSTRAINT chk_finding_fingerprints_not_tombstone CHECK (fingerprint NOT LIKE 'dup:%')
);

CREATE INDEX IF NOT EXISTS idx_finding_fingerprints_finding ON finding_fingerprints (finding_id);

COMMENT ON TABLE finding_fingerprints IS
    'Every fingerprint a finding has had, current and former, per tenant (RFC-043 §6). Ingest resolves an incoming key here.';

-- A finding always owns its current key: when a new finding takes a key that
-- an older finding gave up, the alias moves to the new holder.

-- New findings, once per statement (a batch insert of 500 rows is one INSERT
-- here, not 500).
CREATE OR REPLACE FUNCTION findings_fingerprint_alias_on_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_fingerprints (tenant_id, fingerprint, finding_id, version)
    SELECT n.tenant_id, n.fingerprint, n.id, n.fingerprint_version
    FROM new_findings n
    WHERE n.fingerprint NOT LIKE 'dup:%'
    ON CONFLICT (tenant_id, fingerprint) DO UPDATE
        SET finding_id = EXCLUDED.finding_id, version = EXCLUDED.version
        WHERE finding_fingerprints.finding_id <> EXCLUDED.finding_id
           OR finding_fingerprints.version <> EXCLUDED.version;
    RETURN NULL;
END;
$$;

-- A re-key (recipe migration, asset merge, legacy adoption). The previous key
-- stays: it is an alias of the same finding from now on.
CREATE OR REPLACE FUNCTION findings_fingerprint_alias_on_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.fingerprint LIKE 'dup:%' THEN
        RETURN NULL;
    END IF;
    INSERT INTO finding_fingerprints (tenant_id, fingerprint, finding_id, version)
    VALUES (NEW.tenant_id, NEW.fingerprint, NEW.id, NEW.fingerprint_version)
    ON CONFLICT (tenant_id, fingerprint) DO UPDATE
        SET finding_id = EXCLUDED.finding_id, version = EXCLUDED.version
        WHERE finding_fingerprints.finding_id <> EXCLUDED.finding_id
           OR finding_fingerprints.version <> EXCLUDED.version;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_findings_fingerprint_alias_insert ON findings;
CREATE TRIGGER trg_findings_fingerprint_alias_insert
    AFTER INSERT ON findings
    REFERENCING NEW TABLE AS new_findings
    FOR EACH STATEMENT EXECUTE FUNCTION findings_fingerprint_alias_on_insert();

DROP TRIGGER IF EXISTS trg_findings_fingerprint_alias_update ON findings;
CREATE TRIGGER trg_findings_fingerprint_alias_update
    AFTER UPDATE OF fingerprint, fingerprint_version ON findings
    FOR EACH ROW
    WHEN (NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
          OR NEW.fingerprint_version IS DISTINCT FROM OLD.fingerprint_version)
    EXECUTE FUNCTION findings_fingerprint_alias_on_update();

-- Backfill: every live finding's current key, in batches of 5000 by id.
DO $$
DECLARE
    last_id UUID := '00000000-0000-0000-0000-000000000000';
    next_id UUID;
BEGIN
    LOOP
        SELECT b.id INTO next_id
        FROM (SELECT id FROM findings WHERE id > last_id ORDER BY id LIMIT 5000) b
        ORDER BY b.id DESC
        LIMIT 1;
        EXIT WHEN next_id IS NULL;

        INSERT INTO finding_fingerprints (tenant_id, fingerprint, finding_id, version)
        SELECT f.tenant_id, f.fingerprint, f.id, f.fingerprint_version
        FROM findings f
        WHERE f.id > last_id AND f.id <= next_id
          AND f.fingerprint NOT LIKE 'dup:%'
        ON CONFLICT (tenant_id, fingerprint) DO NOTHING;

        last_id := next_id;
    END LOOP;
END;
$$;
