-- Attachments: tenant-scoped file uploads referenced from markdown content.
--
-- Files are stored externally via the FileStorage interface (local/S3/MinIO).
-- This table tracks metadata + the opaque storage_key used to retrieve bytes.
-- The download endpoint /api/v1/attachments/{id} verifies tenant isolation
-- before serving the file.

CREATE TABLE IF NOT EXISTS attachments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    filename     VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL,
    size         BIGINT NOT NULL,
    storage_key  VARCHAR(500) NOT NULL,
    uploaded_by  UUID NOT NULL REFERENCES users(id),
    -- Optional context linking for cascade cleanup.
    -- context_type: "finding", "retest", "campaign", or "" (general upload)
    -- context_id: the UUID of the linked entity
    context_type VARCHAR(20) NOT NULL DEFAULT '',
    context_id   VARCHAR(36) NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-scoped lookups
CREATE INDEX idx_attachments_tenant ON attachments(tenant_id);
-- Context lookups (e.g., all attachments for a finding)
CREATE INDEX idx_attachments_context ON attachments(tenant_id, context_type, context_id)
    WHERE context_type != '';
-- Cleanup by user (e.g., user deleted → orphan cleanup job)
CREATE INDEX idx_attachments_uploaded_by ON attachments(uploaded_by);
