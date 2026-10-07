-- Undo 001245: recreate easm_seeds from the entries the fold inserted, remove
-- those entries, and drop the discovery column. Entries the fold only
-- updated (an existing "*.v" put back into effect or given discovery) keep
-- their state: there is no record of what they were before.

CREATE TABLE IF NOT EXISTS easm_seeds (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    kind text NOT NULL,
    value text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    discovery_enabled boolean DEFAULT true NOT NULL,
    attested_by uuid,
    attested_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT easm_seeds_pkey PRIMARY KEY (id),
    CONSTRAINT uq_easm_seeds_tenant_kind_value UNIQUE (tenant_id, kind, value),
    CONSTRAINT chk_easm_seeds_kind CHECK (kind = ANY (ARRAY['org_name', 'brand', 'root_domain', 'asn', 'cidr',
        'cloud_account', 'github_org', 'mobile_publisher', 'analytics_id', 'favicon_hash'])),
    CONSTRAINT chk_easm_seeds_label CHECK (length(label) <= 200),
    CONSTRAINT chk_easm_seeds_value CHECK (length(value) >= 1 AND length(value) <= 253),
    CONSTRAINT easm_seeds_attested_by_fkey FOREIGN KEY (attested_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT easm_seeds_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT easm_seeds_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_easm_seeds_tenant_kind ON easm_seeds USING btree (tenant_id, kind) WHERE discovery_enabled;

INSERT INTO easm_seeds (id, tenant_id, kind, value, label, discovery_enabled, attested_by, attested_at, created_by, created_at, updated_at)
SELECT t.id, t.tenant_id, 'root_domain', regexp_replace(lower(t.pattern), '^\*\*?\.', ''), COALESCE(left(t.description, 200), ''),
       t.discovery,
       CASE WHEN t.created_by ~ '^[0-9a-f-]{36}$' AND EXISTS (SELECT 1 FROM users u WHERE u.id::text = t.created_by) THEN t.created_by::uuid END,
       COALESCE(t.approved_at, t.created_at, now()),
       CASE WHEN t.created_by ~ '^[0-9a-f-]{36}$' AND EXISTS (SELECT 1 FROM users u WHERE u.id::text = t.created_by) THEN t.created_by::uuid END,
       COALESCE(t.created_at, now()), now()
FROM scope_targets t
WHERE t.origin = 'seed_migration' AND t.reason LIKE 'Root-domain seed %'
ON CONFLICT (tenant_id, kind, value) DO NOTHING;

DELETE FROM scope_targets WHERE origin = 'seed_migration';

ALTER TABLE scope_targets DROP COLUMN IF EXISTS discovery;
