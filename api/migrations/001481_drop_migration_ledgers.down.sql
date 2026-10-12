-- Recreates the tables (empty) and the normalisation function as they were
-- before 001481. Their rows are not restored: the pre-upgrade backup has them.

CREATE TABLE public.access_control_removed_archive (
    id bigint NOT NULL,
    source_table text NOT NULL,
    row_data jsonb NOT NULL,
    archived_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.access_control_removed_archive IS 'Rows removed with group permission sets (migration 000670 and its contract step); restored by their down migrations';

CREATE SEQUENCE public.access_control_removed_archive_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.access_control_removed_archive_id_seq OWNED BY public.access_control_removed_archive.id;

CREATE TABLE public.asset_properties_pre_001185 (
    asset_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    properties jsonb NOT NULL,
    saved_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.asset_properties_pre_001185 IS 'Asset properties before migration 001185 normalised them (RFC-042 6.3.9); read only by its down migration.';

CREATE TABLE public.asset_type_input_map (
    from_type character varying(50) NOT NULL,
    from_sub_type character varying(50) DEFAULT ''::character varying NOT NULL,
    to_type character varying(50) NOT NULL,
    to_sub_type character varying(50),
    provider character varying(50),
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL
);

COMMENT ON TABLE public.asset_type_input_map IS 'RFC-042 §6.3.8: accepted input (type, sub_type) -> stored (type, sub_type, provider, attributes); generated from api/configs/asset-types.yaml';

CREATE TABLE public.asset_type_legacy_codes (
    code character varying(50) NOT NULL,
    to_type character varying(50) NOT NULL,
    to_sub_type character varying(50)
);

COMMENT ON TABLE public.asset_type_legacy_codes IS 'RFC-042 §6.3.8: what each legacy asset_types code was normalised to by 000684';

CREATE TABLE public.asset_type_reclassifications (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    migration integer NOT NULL,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    rule character varying(20) NOT NULL,
    old_type character varying(50) NOT NULL,
    old_sub_type character varying(50),
    old_provider character varying(50),
    new_type character varying(50) NOT NULL,
    new_sub_type character varying(50),
    new_provider character varying(50),
    added jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.asset_type_reclassifications IS 'RFC-042 §6.3.8: ledger of the asset type normalisation (000684); added = the properties it set, which the down migration removes when unchanged';

CREATE TABLE public.asset_types_legacy_removed (
    code character varying(50) NOT NULL,
    row_data jsonb NOT NULL,
    removed_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.asset_types_legacy_removed IS 'RFC-042 §6.3.8: legacy asset_types rows removed by 000684, restored by its down migration';

CREATE TABLE public.easm_ct_rekey_001018 (
    id uuid NOT NULL,
    old_fingerprint character varying(64) NOT NULL,
    old_state text NOT NULL,
    old_resolved_at timestamp with time zone,
    old_resolution_notes text
);

CREATE TABLE public.granular_permission_backfill (
    role_id uuid NOT NULL,
    permission_id character varying(100) NOT NULL
);

COMMENT ON TABLE public.granular_permission_backfill IS 'Role grants added by migration 000771; its down migration removes exactly these';

CREATE TABLE public.legacy_template_steps_backup_001322 (
    id uuid,
    scan_workflow_id uuid,
    step_key character varying(100),
    name character varying(255),
    description text,
    step_order integer,
    tool character varying(100),
    capabilities text[],
    config jsonb,
    timeout_seconds integer,
    depends_on text[],
    condition_type character varying(50),
    condition_value text,
    max_retries integer,
    retry_delay_seconds integer,
    ui_position_x integer,
    ui_position_y integer,
    created_at timestamp with time zone,
    tool_id uuid,
    prefer_tools text[]
);

CREATE TABLE public.legacy_templates_backup_001322 (
    id uuid,
    description text
);

CREATE TABLE public.technique_applicability_rekey_ledger (
    technique_id character varying(20) NOT NULL,
    old_asset_type character varying(50) NOT NULL,
    dataset_version character varying(20) NOT NULL,
    edge_type character varying(40),
    min_network character varying(20),
    min_credential character varying(20),
    requires_persistence boolean,
    new_asset_type character varying(50) NOT NULL,
    new_sub_type character varying(50) NOT NULL,
    inserted boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.technique_applicability_rekey_ledger IS 'RFC-042 §6.3.8: rows moved from alias asset types by 000457; read by its down migration';

CREATE TABLE public.technique_applicability_subtype_moves (
    migration integer NOT NULL,
    technique_id character varying(20) NOT NULL,
    asset_type character varying(50) NOT NULL,
    old_sub_type character varying(50) NOT NULL,
    new_sub_type character varying(50) NOT NULL,
    dataset_version character varying(20) NOT NULL,
    edge_type character varying(40),
    min_network character varying(20),
    min_credential character varying(20),
    requires_persistence boolean,
    inserted boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.technique_applicability_subtype_moves IS 'RFC-042 §6.3.8: technique_applicability rows moved to another sub-type by a T4a migration; read by its down migration';

ALTER TABLE ONLY public.access_control_removed_archive ALTER COLUMN id SET DEFAULT nextval('public.access_control_removed_archive_id_seq'::regclass);

ALTER TABLE ONLY public.access_control_removed_archive
    ADD CONSTRAINT access_control_removed_archive_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_properties_pre_001185
    ADD CONSTRAINT asset_properties_pre_001185_pkey PRIMARY KEY (asset_id);

ALTER TABLE ONLY public.asset_type_input_map
    ADD CONSTRAINT asset_type_input_map_pkey PRIMARY KEY (from_type, from_sub_type);

ALTER TABLE ONLY public.asset_type_legacy_codes
    ADD CONSTRAINT asset_type_legacy_codes_pkey PRIMARY KEY (code);

ALTER TABLE ONLY public.asset_type_reclassifications
    ADD CONSTRAINT asset_type_reclassifications_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_types_legacy_removed
    ADD CONSTRAINT asset_types_legacy_removed_pkey PRIMARY KEY (code);

ALTER TABLE ONLY public.easm_ct_rekey_001018
    ADD CONSTRAINT easm_ct_rekey_001018_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.granular_permission_backfill
    ADD CONSTRAINT granular_permission_backfill_pkey PRIMARY KEY (role_id, permission_id);

ALTER TABLE ONLY public.technique_applicability_rekey_ledger
    ADD CONSTRAINT technique_applicability_rekey_ledger_pkey PRIMARY KEY (technique_id, old_asset_type, dataset_version);

ALTER TABLE ONLY public.technique_applicability_subtype_moves
    ADD CONSTRAINT technique_applicability_subtype_moves_pkey PRIMARY KEY (migration, technique_id, asset_type, old_sub_type, dataset_version);

CREATE INDEX idx_asset_type_reclassifications_migration ON public.asset_type_reclassifications USING btree (migration, asset_id);

ALTER TABLE ONLY public.asset_properties_pre_001185
    ADD CONSTRAINT asset_properties_pre_001185_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.asset_type_reclassifications
    ADD CONSTRAINT asset_type_reclassifications_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.asset_type_reclassifications
    ADD CONSTRAINT asset_type_reclassifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.asset_properties_pre_001185
    ADD CONSTRAINT fk_asset_properties_pre_001185_tenant_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES public.assets(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.asset_type_reclassifications
    ADD CONSTRAINT fk_asset_type_reclassifications_tenant_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES public.assets(tenant_id, id) ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION public.asset_type_normalise_batch(p_after uuid, p_batch integer, p_migration integer, OUT last_id uuid, OUT moved integer)
 RETURNS record
 LANGUAGE plpgsql
AS $function$
DECLARE
    r            record;
    m            record;
    new_type     text;
    new_sub      text;
    new_provider text;
    attrs        jsonb;
    rule         text;
    left_sub     text;
    added        jsonb;
    label_old    text;
    label_new    text;
BEGIN
    moved := 0;
    SELECT page.id INTO last_id FROM (
        SELECT id FROM assets
        WHERE p_after IS NULL OR id > p_after
        ORDER BY id
        LIMIT p_batch
    ) page
    ORDER BY page.id DESC
    LIMIT 1;
    IF last_id IS NULL THEN
        RETURN;
    END IF;

    FOR r IN
        SELECT a.id, a.tenant_id, a.asset_type, NULLIF(a.sub_type, '') AS sub_type,
               a.provider, a.properties
        FROM assets a
        LEFT JOIN asset_types t ON t.code = a.asset_type
        WHERE (p_after IS NULL OR a.id > p_after) AND a.id <= last_id
          AND NOT (COALESCE(t.is_storable, false)
                   AND (NULLIF(a.sub_type, '') IS NULL OR a.sub_type = ANY (t.sub_types)))
        ORDER BY a.id
    LOOP
        new_provider := NULL;
        attrs := '{}'::jsonb;
        left_sub := r.sub_type;

        SELECT * INTO m FROM asset_type_input_map
        WHERE from_type = r.asset_type AND from_sub_type = COALESCE(r.sub_type, '');
        IF FOUND THEN
            rule := 'input';
            new_type := m.to_type;
            new_sub := m.to_sub_type;
            new_provider := m.provider;
            attrs := m.attributes;
            left_sub := NULL; -- the sub-type was the input itself
        ELSE
            SELECT * INTO m FROM asset_type_input_map
            WHERE from_type = r.asset_type AND from_sub_type = '';
            IF FOUND THEN
                rule := 'alias';
                new_type := m.to_type;
                new_sub := m.to_sub_type;
                new_provider := m.provider;
                attrs := m.attributes;
            ELSE
                SELECT * INTO m FROM asset_type_legacy_codes WHERE code = r.asset_type;
                IF FOUND THEN
                    rule := 'legacy_code';
                    new_type := m.to_type;
                    new_sub := m.to_sub_type;
                    attrs := jsonb_build_object('x_native_type', r.asset_type);
                ELSIF EXISTS (SELECT 1 FROM asset_types WHERE code = r.asset_type AND is_storable) THEN
                    rule := 'undeclared';
                    new_type := r.asset_type;
                    new_sub := NULL;
                ELSE
                    -- Not a registry type and not a known legacy code: kept
                    -- as an unclassified asset that remembers its type.
                    rule := 'legacy_code';
                    new_type := 'unclassified';
                    new_sub := NULL;
                    attrs := jsonb_build_object('x_native_type', r.asset_type);
                END IF;
            END IF;
        END IF;

        -- A sub-type the input did not account for is kept when it is a
        -- declared kind of the new type, else recorded as an attribute.
        IF left_sub IS NOT NULL AND left_sub IS DISTINCT FROM new_sub THEN
            IF new_sub IS NULL AND EXISTS (
                SELECT 1 FROM asset_types WHERE code = new_type AND left_sub = ANY (sub_types)
            ) THEN
                new_sub := left_sub;
            ELSE
                attrs := attrs || jsonb_build_object('x_native_sub_type', left_sub);
            END IF;
        END IF;

        -- A provider the asset already names wins over the one the input
        -- implied (cloud_account/aws on a gcp account); the input's value is
        -- then kept as the native sub-type instead of a contradicting
        -- properties.provider.
        IF COALESCE(NULLIF(r.provider, ''), 'other') <> 'other'
           AND attrs ? 'provider' AND attrs->>'provider' <> r.provider THEN
            attrs := (attrs - 'provider') || jsonb_build_object('x_native_sub_type', COALESCE(r.sub_type, r.asset_type));
        END IF;

        -- Never overwrite: only the properties the asset does not have.
        SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{}'::jsonb) INTO added
        FROM jsonb_each(attrs) e
        WHERE NOT (r.properties ? e.key);

        IF new_provider IS NULL OR COALESCE(NULLIF(r.provider, ''), 'other') <> 'other' THEN
            new_provider := r.provider;
        END IF;

        UPDATE assets
           SET asset_type = new_type,
               sub_type = new_sub,
               provider = new_provider,
               properties = properties || added
         WHERE id = r.id;

        INSERT INTO asset_type_reclassifications
            (migration, tenant_id, asset_id, rule, old_type, old_sub_type, old_provider,
             new_type, new_sub_type, new_provider, added)
        VALUES (p_migration, r.tenant_id, r.id, rule, r.asset_type, r.sub_type, r.provider,
                new_type, new_sub, new_provider, added);

        label_old := r.asset_type || COALESCE('/' || r.sub_type, '');
        label_new := new_type || COALESCE('/' || new_sub, '');
        INSERT INTO asset_state_history
            (tenant_id, asset_id, change_type, field, old_value, new_value, reason, source, metadata)
        VALUES (r.tenant_id, r.id, 'reclassified', 'asset_type', label_old, label_new,
                'Asset type normalised to the asset type registry (RFC-042 §6.3.8)', 'system',
                jsonb_build_object('migration', p_migration, 'rule', rule));

        moved := moved + 1;
    END LOOP;
END $function$

;
