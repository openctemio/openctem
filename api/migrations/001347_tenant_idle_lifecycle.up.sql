-- Idle Free workspaces (docs/architecture/idle-workspaces.md): where each
-- Free organization is in the idle lifecycle (reminded at 60 days without a
-- sign-in, read-only at 90, final warning at 113, deletion due at 120) and a
-- platform administrator's exemption. A missing row is "active". New, empty
-- table: nothing changes for existing organizations until the daily sweep
-- runs, and only Free organizations are swept.

CREATE TABLE tenant_idle_lifecycle (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    stage            text NOT NULL DEFAULT 'active',
    stage_changed_at timestamp with time zone NOT NULL DEFAULT now(),
    exempt           boolean NOT NULL DEFAULT false,
    exempt_reason    text,
    exempt_by        uuid,
    exempt_at        timestamp with time zone,
    CONSTRAINT chk_tenant_idle_lifecycle_stage
        CHECK (stage IN ('active', 'reminded', 'read_only', 'final_warning', 'deletion_due')),
    CONSTRAINT chk_tenant_idle_lifecycle_exempt_reason
        CHECK (NOT exempt OR (exempt_reason IS NOT NULL AND char_length(exempt_reason) BETWEEN 1 AND 500))
);
