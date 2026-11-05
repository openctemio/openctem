-- Where a version-match finding is observed (docs/architecture/vulnerability-matching.md,
-- "Locations"). One web server answers on several origins of one host (http:80,
-- https:443, http:8080), and each origin is its own service asset. The matcher
-- keeps one finding per host, product, version and CVE on the oldest of those
-- service assets, and one location row per service it sees the software on,
-- each with its own evidence, sightings and state:
--   affected      the vulnerable version is observed there;
--   fixed         another, evaluated version displaced it there;
--   not_affected  the advisory no longer covers the version seen there.
-- The finding stays open while any location is affected.
--
-- location_key is the network identity (asset, CVE, port, transport) of the
-- location, the key the matcher used for a finding of its own before: a
-- location belongs to one finding of the tenant.
--
-- finding_location_merges is the recovery journal of the command that folds
-- the per-origin duplicates stored before locations existed
-- (cmd/vulnmatch-locations): what each fold changed, so `-down` can put it back.
--
-- Live impact: two new, empty tables and one more allowed timeline entry type
-- (a NOT VALID constraint swap, no table rewrite). Nothing to backfill: the
-- matcher writes the locations of its findings on its next pass.

CREATE TABLE finding_locations (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id     uuid NOT NULL,
    asset_id       uuid NOT NULL,
    location_key   text NOT NULL CHECK (length(location_key) BETWEEN 1 AND 256),
    port           integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
    transport      varchar(8) NOT NULL DEFAULT '' CHECK (length(transport) <= 8),
    -- The software link the location was matched on (asset_software): product,
    -- version and the link's location on the asset.
    product_id     uuid,
    version_id     uuid,
    version        text NOT NULL DEFAULT '' CHECK (length(version) <= 128),
    link_location  text NOT NULL DEFAULT '' CHECK (length(link_location) <= 512),
    -- What the version was read from (a banner, a header), bounded, e-mail
    -- addresses masked.
    evidence       text NOT NULL DEFAULT '' CHECK (length(evidence) <= 512),
    state          varchar(16) NOT NULL DEFAULT 'affected'
                   CHECK (state IN ('affected', 'fixed', 'not_affected')),
    state_reason   varchar(32) NOT NULL DEFAULT '' CHECK (length(state_reason) <= 32),
    state_at       timestamptz NOT NULL DEFAULT now(),
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_finding_locations_finding FOREIGN KEY (finding_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_locations_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX ux_finding_locations_key ON finding_locations (tenant_id, location_key);
CREATE INDEX idx_finding_locations_finding ON finding_locations (tenant_id, finding_id);
CREATE INDEX idx_finding_locations_asset ON finding_locations (tenant_id, asset_id);

COMMENT ON TABLE finding_locations IS
    'Services (origins) a version-match finding is observed on, one row per service, each with its own evidence, sightings and state (affected, fixed, not_affected).';

CREATE TABLE finding_location_merges (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id             uuid NOT NULL,
    survivor_id        uuid NOT NULL,
    loser_id           uuid NOT NULL,
    -- The finding columns the fold changed, before and after it.
    survivor_before    jsonb NOT NULL,
    survivor_after     jsonb NOT NULL,
    loser_before       jsonb NOT NULL,
    -- Per table: the keys of the loser's rows moved to the survivor, and the
    -- rows dropped because the survivor already had their unique key.
    moved              jsonb NOT NULL DEFAULT '{}',
    dropped            jsonb NOT NULL DEFAULT '{}',
    built_location_ids uuid[] NOT NULL DEFAULT '{}',
    -- clock_timestamp(): the folds of one transaction are reverted newest first.
    merged_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    reverted_at        timestamptz,
    CONSTRAINT fk_finding_location_merges_survivor FOREIGN KEY (survivor_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_location_merges_loser FOREIGN KEY (loser_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX ux_finding_location_merges_open ON finding_location_merges (tenant_id, loser_id)
    WHERE reverted_at IS NULL;
CREATE INDEX idx_finding_location_merges_run ON finding_location_merges (tenant_id, run_id);
CREATE INDEX idx_finding_location_merges_survivor ON finding_location_merges (tenant_id, survivor_id);

COMMENT ON TABLE finding_location_merges IS
    'Recovery journal of the version-match location merge: what each fold changed, so it can be reverted.';

DO $$
DECLARE
    vals text[];
    added text[] := ARRAY['location_changed'];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND NOT vals @> added THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM (SELECT DISTINCT unnest(vals || added) AS v) u));
    END IF;
END;
$$;
