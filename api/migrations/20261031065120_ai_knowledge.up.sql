-- AI knowledge sources (RFC-139, docs/architecture/ai-knowledge.md).
--
-- An organization gives its AI agents prose that exists nowhere else in the
-- platform (runbooks, conventions, architecture notes). Facts the platform
-- already models (assets, owners, criticality, SLAs, vulnerability intel)
-- stay live data and are never copied here.
--
--   ai_knowledge_sources       a named container: visibility (organization or
--                              teams), data class, approval state.
--   ai_knowledge_source_teams  the teams a team-restricted source is visible
--                              to (an AI agent sees it when it is a member).
--   ai_knowledge_documents     one version of one document. Editing a document
--                              adds a pending version (same lineage); the
--                              approved one keeps serving until the new one is
--                              approved, so an edit never reaches an AI agent
--                              without a second person.
--   ai_knowledge_chunks        sections of a document version: the unit of
--                              retrieval (Postgres full-text, 'simple'
--                              configuration, plus trigram on the title) and of
--                              citation.
--   ai_run_knowledge           which excerpts a run saw (run-local ordinal,
--                              chunk, document version digest, score, cited).
--                              No text: deleting a document erases it.
--
-- ai_runs gains retrieval_mode and retrieval_index: how the run retrieved.
--
-- Permissions ai_knowledge:read and ai_knowledge:manage go to the owner and
-- administrator roles; AI agents never hold them (deny list in code).
--
-- Live impact: five new tables, two nullable columns on ai_runs (no rewrite,
-- no backfill), two permission rows and four role_permissions rows.

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
VALUES
    ('ai_knowledge:read', 'ai_triage', 'View AI Knowledge',
     'View the knowledge sources AI agents may retrieve and preview what an AI agent would retrieve', true, now()),
    ('ai_knowledge:manage', 'ai_triage', 'Manage AI Knowledge',
     'Add, approve, reject, disable and delete knowledge sources and documents for AI agents', true, now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (id, role_id, permission_id, created_at)
SELECT uuid_generate_v7(), r.id, p.id, now()
FROM roles r
CROSS JOIN (VALUES ('ai_knowledge:read'), ('ai_knowledge:manage')) AS p(id)
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
  AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = p.id);

CREATE TABLE ai_knowledge_sources (
    id              uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            varchar(120) NOT NULL,
    description     varchar(1000) NOT NULL DEFAULT '',
    origin          varchar(16)  NOT NULL DEFAULT 'upload',
    visibility      varchar(16)  NOT NULL DEFAULT 'organization',
    data_class      varchar(16)  NOT NULL DEFAULT 'internal',
    status          varchar(16)  NOT NULL DEFAULT 'pending',
    created_by      uuid         REFERENCES users(id) ON DELETE SET NULL,
    decided_by      uuid         REFERENCES users(id) ON DELETE SET NULL,
    decided_at      timestamptz,
    self_approved   boolean      NOT NULL DEFAULT false,
    rejected_reason varchar(500),
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_knowledge_sources PRIMARY KEY (id),
    CONSTRAINT uq_ai_knowledge_sources_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT chk_ai_knowledge_sources_name CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    CONSTRAINT chk_ai_knowledge_sources_origin CHECK (origin IN ('upload', 'url', 'git', 'confluence')),
    CONSTRAINT chk_ai_knowledge_sources_visibility CHECK (visibility IN ('organization', 'teams')),
    CONSTRAINT chk_ai_knowledge_sources_class CHECK (data_class IN ('internal', 'restricted')),
    CONSTRAINT chk_ai_knowledge_sources_status CHECK (status IN ('pending', 'approved', 'rejected', 'disabled')),
    CONSTRAINT chk_ai_knowledge_sources_decided CHECK ((status = 'pending') OR (decided_at IS NOT NULL))
);
CREATE UNIQUE INDEX uq_ai_knowledge_sources_name ON ai_knowledge_sources (tenant_id, lower(name));
CREATE INDEX idx_ai_knowledge_sources_created_by ON ai_knowledge_sources (created_by) WHERE created_by IS NOT NULL;
CREATE INDEX idx_ai_knowledge_sources_decided_by ON ai_knowledge_sources (decided_by) WHERE decided_by IS NOT NULL;
COMMENT ON TABLE ai_knowledge_sources IS
    'Prose an organization gives its AI agents. Retrieved only when approved, by AI agents allowed by its visibility and data class.';

CREATE POLICY ai_knowledge_sources_tenant_isolation ON ai_knowledge_sources
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE ai_knowledge_source_teams (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id uuid NOT NULL,
    group_id  uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    CONSTRAINT pk_ai_knowledge_source_teams PRIMARY KEY (source_id, group_id),
    CONSTRAINT fk_ai_knowledge_source_teams_source FOREIGN KEY (source_id, tenant_id)
        REFERENCES ai_knowledge_sources (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX idx_ai_knowledge_source_teams_group ON ai_knowledge_source_teams (group_id);
CREATE INDEX idx_ai_knowledge_source_teams_tenant ON ai_knowledge_source_teams (tenant_id);

CREATE FUNCTION refuse_foreign_ai_knowledge_team() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = NEW.group_id AND g.tenant_id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'a knowledge source team must belong to the same organization'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_foreign_ai_knowledge_team
    BEFORE INSERT OR UPDATE ON ai_knowledge_source_teams
    FOR EACH ROW EXECUTE FUNCTION refuse_foreign_ai_knowledge_team();

CREATE POLICY ai_knowledge_source_teams_tenant_isolation ON ai_knowledge_source_teams
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE ai_knowledge_documents (
    id                uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id         uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id         uuid         NOT NULL,
    lineage_id        uuid         NOT NULL,
    version           integer      NOT NULL DEFAULT 1,
    title             varchar(200) NOT NULL,
    status            varchar(16)  NOT NULL DEFAULT 'pending',
    quarantined       boolean      NOT NULL DEFAULT false,
    quarantine_reason varchar(64),
    content_sha256    varchar(71)  NOT NULL,
    bytes             integer      NOT NULL,
    chunks            integer      NOT NULL DEFAULT 0,
    created_by        uuid         REFERENCES users(id) ON DELETE SET NULL,
    decided_by        uuid         REFERENCES users(id) ON DELETE SET NULL,
    decided_at        timestamptz,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_knowledge_documents PRIMARY KEY (id),
    CONSTRAINT uq_ai_knowledge_documents_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT uq_ai_knowledge_documents_version UNIQUE (lineage_id, version),
    CONSTRAINT fk_ai_knowledge_documents_source FOREIGN KEY (source_id, tenant_id)
        REFERENCES ai_knowledge_sources (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_ai_knowledge_documents_title CHECK (length(btrim(title)) BETWEEN 1 AND 200),
    CONSTRAINT chk_ai_knowledge_documents_status CHECK (status IN ('pending', 'approved', 'rejected', 'superseded')),
    CONSTRAINT chk_ai_knowledge_documents_quarantine CHECK (quarantined = (quarantine_reason IS NOT NULL)
        AND (quarantine_reason IS NULL OR quarantine_reason ~ '^[a-z_]{1,64}$')),
    CONSTRAINT chk_ai_knowledge_documents_digest CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT chk_ai_knowledge_documents_size CHECK (bytes BETWEEN 1 AND 262144 AND chunks BETWEEN 0 AND 400
        AND version >= 1)
);
-- At most one approved version per document: the one AI agents retrieve.
CREATE UNIQUE INDEX uq_ai_knowledge_documents_approved ON ai_knowledge_documents (lineage_id) WHERE status = 'approved';
CREATE INDEX idx_ai_knowledge_documents_source ON ai_knowledge_documents (tenant_id, source_id, status);
CREATE INDEX idx_ai_knowledge_documents_created_by ON ai_knowledge_documents (created_by) WHERE created_by IS NOT NULL;
CREATE INDEX idx_ai_knowledge_documents_decided_by ON ai_knowledge_documents (decided_by) WHERE decided_by IS NOT NULL;
COMMENT ON TABLE ai_knowledge_documents IS
    'One version of one knowledge document (lineage_id groups the versions). Only the approved version is retrieved.';
COMMENT ON COLUMN ai_knowledge_documents.quarantine_reason IS
    'Why ingest flagged the text (prompt_injection, ...): approving needs an explicit acknowledgement.';

CREATE POLICY ai_knowledge_documents_tenant_isolation ON ai_knowledge_documents
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE ai_knowledge_chunks (
    id          uuid          NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id   uuid          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    document_id uuid          NOT NULL,
    ordinal     integer       NOT NULL,
    title       varchar(300)  NOT NULL DEFAULT '',
    body        text          NOT NULL,
    search      tsvector      GENERATED ALWAYS AS (
                    setweight(to_tsvector('simple'::regconfig, coalesce(title, '')), 'A')
                    || setweight(to_tsvector('simple'::regconfig, body), 'D')) STORED,
    CONSTRAINT pk_ai_knowledge_chunks PRIMARY KEY (id),
    CONSTRAINT uq_ai_knowledge_chunks_ordinal UNIQUE (document_id, ordinal),
    CONSTRAINT fk_ai_knowledge_chunks_document FOREIGN KEY (document_id, tenant_id)
        REFERENCES ai_knowledge_documents (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_ai_knowledge_chunks_body CHECK (length(body) BETWEEN 1 AND 4000 AND ordinal BETWEEN 0 AND 399)
);
CREATE INDEX idx_ai_knowledge_chunks_tenant ON ai_knowledge_chunks (tenant_id);
CREATE INDEX idx_ai_knowledge_chunks_search ON ai_knowledge_chunks USING gin (search);
CREATE INDEX idx_ai_knowledge_chunks_title_trgm ON ai_knowledge_chunks USING gin (title gin_trgm_ops);
COMMENT ON TABLE ai_knowledge_chunks IS
    'Sections of a knowledge document version: the unit of retrieval and citation. Untrusted text: masked and fenced before a model sees it.';

CREATE POLICY ai_knowledge_chunks_tenant_isolation ON ai_knowledge_chunks
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

ALTER TABLE ai_runs
    ADD COLUMN retrieval_mode  varchar(16),
    ADD COLUMN retrieval_index varchar(32),
    ADD CONSTRAINT chk_ai_runs_retrieval CHECK (
        (retrieval_mode IS NULL OR retrieval_mode IN ('none', 'lexical', 'hybrid', 'vector'))
        AND (retrieval_index IS NULL OR retrieval_index ~ '^[a-z0-9_.-]{1,32}$'));
COMMENT ON COLUMN ai_runs.retrieval_mode IS
    'How the run retrieved knowledge: none, lexical, hybrid or vector (NULL: before knowledge retrieval existed).';

CREATE TABLE ai_run_knowledge (
    tenant_id      uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id         uuid        NOT NULL,
    ordinal        smallint    NOT NULL,
    chunk_id       uuid        REFERENCES ai_knowledge_chunks(id) ON DELETE SET NULL,
    document_id    uuid,
    source_id      uuid,
    version_digest varchar(71) NOT NULL,
    score          real        NOT NULL DEFAULT 0,
    cited          boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_run_knowledge PRIMARY KEY (run_id, ordinal),
    CONSTRAINT fk_ai_run_knowledge_run FOREIGN KEY (run_id, tenant_id)
        REFERENCES ai_runs (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_ai_run_knowledge_ordinal CHECK (ordinal BETWEEN 1 AND 64),
    CONSTRAINT chk_ai_run_knowledge_digest CHECK (version_digest ~ '^sha256:[0-9a-f]{64}$')
);
CREATE INDEX idx_ai_run_knowledge_tenant ON ai_run_knowledge (tenant_id);
CREATE INDEX idx_ai_run_knowledge_chunk ON ai_run_knowledge (chunk_id) WHERE chunk_id IS NOT NULL;
CREATE INDEX idx_ai_run_knowledge_document ON ai_run_knowledge (tenant_id, document_id) WHERE document_id IS NOT NULL;
COMMENT ON TABLE ai_run_knowledge IS
    'Knowledge excerpts a run saw, by run-local ordinal (cited as kb:<ordinal>). Ids and digests only, never text.';

CREATE POLICY ai_run_knowledge_tenant_isolation ON ai_run_knowledge
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
