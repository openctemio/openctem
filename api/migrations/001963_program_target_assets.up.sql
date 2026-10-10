-- Which assets are a program's targets (RFC-065 §16.8).
--
-- Program targets go through the standard asset ingest; this table records
-- the assets that ingest named for each program, with the program item they
-- come from. The program assignment pass treats them as the program's
-- targets next to the assets its entries cover (a mobile app or a
-- repository has no entry and is never scanned, but is still the
-- program's).
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS bounty_program_target_assets (
    tenant_id  uuid        NOT NULL,
    program_id uuid        NOT NULL,
    asset_id   uuid        NOT NULL,
    item_key   text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, program_id, asset_id),
    CONSTRAINT fk_bounty_program_target_assets_program FOREIGN KEY (tenant_id, program_id)
        REFERENCES bounty_programs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_bounty_program_target_assets_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_bounty_program_target_assets_key CHECK (length(item_key) BETWEEN 1 AND 600)
);

CREATE INDEX IF NOT EXISTS idx_bounty_program_target_assets_asset
    ON bounty_program_target_assets (tenant_id, asset_id);
