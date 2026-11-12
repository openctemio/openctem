-- The example extension's one table, in its own schema (search_path puts the
-- extension schema first). It references the core only by tenant id.
CREATE TABLE IF NOT EXISTS example_notes (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    body       TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS example_notes_tenant_idx ON example_notes (tenant_id, id);
