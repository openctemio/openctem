-- Tenant lifecycles: an organization's sub-statuses and lifecycle schemes on
-- top of the canonical finding statuses (docs/rfcs/RFC-110-tenant-lifecycles.md).
-- New, empty tables and one nullable column on findings (a catalog change);
-- the composite foreign key, its validation and the index follow in their own
-- migrations.

-- A sub-status is an organization's label bound for ever to one canonical
-- status (and, under a closed status, to one closure reason).
CREATE TABLE IF NOT EXISTS lifecycle_sub_statuses (
    id               uuid        PRIMARY KEY,
    tenant_id        uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    object_kind      varchar(32) NOT NULL DEFAULT 'finding',
    canonical_status varchar(30) NOT NULL,
    closure_reason   varchar(64),
    key              varchar(40) NOT NULL,
    name             varchar(64) NOT NULL,
    labels           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    description      varchar(500) NOT NULL DEFAULT '',
    color            varchar(16) NOT NULL,
    sort_order       integer     NOT NULL DEFAULT 0,
    archived_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT NOW(),
    created_by       uuid        REFERENCES users(id) ON DELETE SET NULL,
    updated_at       timestamptz NOT NULL DEFAULT NOW(),
    updated_by       uuid        REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_lifecycle_sub_statuses_kind CHECK (object_kind IN ('finding')),
    CONSTRAINT chk_lifecycle_sub_statuses_status CHECK (canonical_status IN (
        'new', 'confirmed', 'in_progress', 'fix_applied', 'resolved', 'false_positive', 'accepted', 'duplicate')),
    -- A closed status binds a closure reason; an open one has none.
    CONSTRAINT chk_lifecycle_sub_statuses_reason CHECK (
        (canonical_status IN ('resolved', 'false_positive', 'accepted', 'duplicate')) = (closure_reason IS NOT NULL)),
    CONSTRAINT chk_lifecycle_sub_statuses_key CHECK (key ~ '^[a-z][a-z0-9_]{1,39}$'),
    CONSTRAINT chk_lifecycle_sub_statuses_labels CHECK (jsonb_typeof(labels) = 'object'),
    CONSTRAINT uq_lifecycle_sub_statuses_key UNIQUE (tenant_id, object_kind, key),
    -- The target of the findings composite foreign key.
    CONSTRAINT uq_lifecycle_sub_statuses_status UNIQUE (tenant_id, id, canonical_status)
);

COMMENT ON TABLE lifecycle_sub_statuses IS
    'An organization''s finding sub-statuses, each bound to one canonical status (and closure reason); never deleted, only archived';

-- The category of a sub-status never changes: a rename keeps its meaning,
-- and a finding that carries it can never end up under another status.
CREATE OR REPLACE FUNCTION lifecycle_sub_status_category_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.object_kind IS DISTINCT FROM OLD.object_kind
       OR NEW.canonical_status IS DISTINCT FROM OLD.canonical_status
       OR NEW.closure_reason IS DISTINCT FROM OLD.closure_reason
       OR NEW.key IS DISTINCT FROM OLD.key THEN
        RAISE EXCEPTION 'the category and key of a sub-status cannot change'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION lifecycle_sub_status_category_guard() IS
    'Refuses a change of a sub-status tenant, kind, canonical status, closure reason or key';

CREATE TRIGGER trg_lifecycle_sub_statuses_category
    BEFORE UPDATE ON lifecycle_sub_statuses
    FOR EACH ROW
    EXECUTE FUNCTION lifecycle_sub_status_category_guard();

-- A lifecycle scheme: which moves between sub-statuses exist and which extra
-- constraints they carry. context NULL is the default scheme; otherwise the
-- first scheme (by priority) whose context matches a finding applies.
CREATE TABLE IF NOT EXISTS lifecycle_schemes (
    id                   uuid        PRIMARY KEY,
    tenant_id            uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    object_kind          varchar(32) NOT NULL DEFAULT 'finding',
    key                  varchar(40) NOT NULL,
    name                 varchar(64) NOT NULL,
    description          varchar(500) NOT NULL DEFAULT '',
    priority             integer     NOT NULL DEFAULT 0,
    context              jsonb,
    published_version_id uuid,
    archived_at          timestamptz,
    created_at           timestamptz NOT NULL DEFAULT NOW(),
    created_by           uuid        REFERENCES users(id) ON DELETE SET NULL,
    updated_at           timestamptz NOT NULL DEFAULT NOW(),
    updated_by           uuid        REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_lifecycle_schemes_kind CHECK (object_kind IN ('finding')),
    CONSTRAINT chk_lifecycle_schemes_key CHECK (key ~ '^[a-z][a-z0-9_]{1,39}$'),
    CONSTRAINT chk_lifecycle_schemes_context CHECK (context IS NULL OR jsonb_typeof(context) = 'array'),
    CONSTRAINT uq_lifecycle_schemes_key UNIQUE (tenant_id, object_kind, key),
    CONSTRAINT uq_lifecycle_schemes_tenant_id UNIQUE (tenant_id, id)
);

-- At most one default (context-free) scheme per kind among the live ones.
CREATE UNIQUE INDEX IF NOT EXISTS uq_lifecycle_schemes_default
    ON lifecycle_schemes (tenant_id, object_kind)
    WHERE context IS NULL AND archived_at IS NULL;

COMMENT ON TABLE lifecycle_schemes IS
    'An organization''s lifecycle schemes for findings: the default one (context NULL) and context schemes picked by priority';

CREATE TABLE IF NOT EXISTS lifecycle_scheme_versions (
    id           uuid        PRIMARY KEY,
    tenant_id    uuid        NOT NULL,
    scheme_id    uuid        NOT NULL,
    version      integer     NOT NULL,
    state        varchar(16) NOT NULL DEFAULT 'draft',
    spec         jsonb       NOT NULL,
    spec_hash    varchar(64) NOT NULL,
    note         varchar(500) NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT NOW(),
    created_by   uuid        REFERENCES users(id) ON DELETE SET NULL,
    published_at timestamptz,
    published_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    -- A version belongs to a scheme of its own tenant.
    CONSTRAINT fk_lifecycle_scheme_versions_scheme FOREIGN KEY (tenant_id, scheme_id)
        REFERENCES lifecycle_schemes (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_lifecycle_scheme_versions_state CHECK (state IN ('draft', 'published', 'superseded')),
    CONSTRAINT chk_lifecycle_scheme_versions_version CHECK (version > 0),
    CONSTRAINT chk_lifecycle_scheme_versions_spec CHECK (jsonb_typeof(spec) = 'object'),
    CONSTRAINT uq_lifecycle_scheme_versions_version UNIQUE (scheme_id, version),
    CONSTRAINT uq_lifecycle_scheme_versions_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_scheme_versions_tenant ON lifecycle_scheme_versions (tenant_id);

-- One draft per scheme.
CREATE UNIQUE INDEX IF NOT EXISTS uq_lifecycle_scheme_versions_draft
    ON lifecycle_scheme_versions (scheme_id)
    WHERE state = 'draft';

-- The published version of a scheme is one of its own versions.
ALTER TABLE lifecycle_schemes
    ADD CONSTRAINT fk_lifecycle_schemes_published FOREIGN KEY (tenant_id, published_version_id)
        REFERENCES lifecycle_scheme_versions (tenant_id, id) DEFERRABLE INITIALLY DEFERRED;

COMMENT ON TABLE lifecycle_scheme_versions IS
    'Versions of a lifecycle scheme: one draft, the published one and the superseded ones; a published spec never changes';

-- A published or superseded version is history: its spec, hash and number
-- never change, it never goes back to draft, and a superseded one stays
-- superseded.
CREATE OR REPLACE FUNCTION lifecycle_scheme_version_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state <> 'draft' AND (
           NEW.spec IS DISTINCT FROM OLD.spec
        OR NEW.spec_hash IS DISTINCT FROM OLD.spec_hash
        OR NEW.version IS DISTINCT FROM OLD.version
        OR NEW.scheme_id IS DISTINCT FROM OLD.scheme_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.state = 'draft') THEN
        RAISE EXCEPTION 'a published lifecycle version cannot change'
            USING ERRCODE = 'check_violation';
    END IF;
    -- published -> superseded is the only state change after publish; a
    -- rollback publishes a new version copied from an old one.
    IF OLD.state = 'superseded' AND NEW.state <> 'superseded' THEN
        RAISE EXCEPTION 'a superseded lifecycle version cannot change state'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION lifecycle_scheme_version_guard() IS
    'Keeps published and superseded lifecycle versions immutable (a published one may only become superseded)';

CREATE TRIGGER trg_lifecycle_scheme_versions_immutable
    BEFORE UPDATE ON lifecycle_scheme_versions
    FOR EACH ROW
    EXECUTE FUNCTION lifecycle_scheme_version_guard();

-- The finding's sub-status: NULL means the default label of its status.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS sub_status_id uuid;

COMMENT ON COLUMN findings.sub_status_id IS
    'The organization sub-status of the finding (lifecycle_sub_statuses), always one of its canonical status; NULL = the default label';
