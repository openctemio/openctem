-- Recreate asset_sources, empty (the rows dropped by the up migration are not
-- restored). The source_id foreign key is added only while data_sources exists.

CREATE TABLE IF NOT EXISTS asset_sources (
    id uuid DEFAULT uuid_generate_v7() NOT NULL,
    asset_id uuid NOT NULL,
    source_type source_type NOT NULL,
    source_id uuid,
    first_seen_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    source_ref character varying(255),
    contributed_data jsonb DEFAULT '{}'::jsonb,
    confidence integer DEFAULT 100,
    is_primary boolean DEFAULT false,
    seen_count integer DEFAULT 1,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_asset_sources_confidence CHECK (((confidence >= 0) AND (confidence <= 100))),
    CONSTRAINT asset_sources_pkey PRIMARY KEY (id),
    CONSTRAINT asset_sources_unique UNIQUE (asset_id, source_type, source_id),
    CONSTRAINT asset_sources_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

COMMENT ON TABLE asset_sources IS 'Track which data sources discovered each asset';

DO $$
BEGIN
    IF to_regclass('public.data_sources') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'asset_sources_source_id_fkey') THEN
        ALTER TABLE asset_sources
            ADD CONSTRAINT asset_sources_source_id_fkey FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_asset_sources_asset_primary ON asset_sources USING btree (asset_id) WHERE (is_primary = true);
CREATE INDEX IF NOT EXISTS idx_asset_sources_last_seen ON asset_sources USING btree (last_seen_at);
CREATE INDEX IF NOT EXISTS idx_asset_sources_source ON asset_sources USING btree (source_id) WHERE (source_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_asset_sources_source_type ON asset_sources USING btree (source_type);

DROP TRIGGER IF EXISTS trigger_asset_sources_updated_at ON asset_sources;
CREATE TRIGGER trigger_asset_sources_updated_at BEFORE UPDATE ON asset_sources FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
