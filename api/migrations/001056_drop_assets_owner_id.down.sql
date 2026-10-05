-- Restores assets.owner_id from the asset_owners rows derived from owner_ref
-- (the only rows the column ever held), earliest first, in batches.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $$
DECLARE
    cursor_id uuid := NULL;
    last_id   uuid;
BEGIN
    LOOP
        SELECT page.asset_id INTO last_id FROM (
            SELECT DISTINCT asset_id FROM asset_owners
            WHERE assignment_source = 'owner_ref' AND user_id IS NOT NULL
              AND (cursor_id IS NULL OR asset_id > cursor_id)
            ORDER BY asset_id
            LIMIT 5000
        ) page
        ORDER BY page.asset_id DESC
        LIMIT 1;
        EXIT WHEN last_id IS NULL;

        UPDATE assets a
           SET owner_id = src.user_id
          FROM (
              SELECT DISTINCT ON (ao.asset_id) ao.asset_id, ao.user_id
              FROM asset_owners ao
              WHERE ao.assignment_source = 'owner_ref' AND ao.user_id IS NOT NULL
                AND (cursor_id IS NULL OR ao.asset_id > cursor_id)
                AND ao.asset_id <= last_id
              ORDER BY ao.asset_id, ao.assigned_at, ao.id
          ) src
         WHERE a.id = src.asset_id;

        cursor_id := last_id;
    END LOOP;
END $$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

CREATE INDEX IF NOT EXISTS idx_assets_owner_id ON assets (owner_id);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_owner ON assets (tenant_id, owner_id) WHERE owner_id IS NOT NULL;
