-- expand-contract-ok: additive only; the check reads the column name "truncated" as TRUNCATE
-- Finding evidence (docs/architecture/finding-evidence.md): the typed proof a
-- tool attached to a detection or a retest attempt (an HTTP exchange, text,
-- a file excerpt, ...), masked, with its secret values split out and
-- encrypted. Kept apart from findings so no list, export, notification,
-- ticket or AI prompt can carry it.

CREATE TABLE finding_evidence (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id       uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    retest_id        uuid REFERENCES finding_retests(id) ON DELETE CASCADE,
    origin           varchar(16) NOT NULL CHECK (origin IN ('detection', 'retest')),
    kind             varchar(64) NOT NULL CHECK (char_length(kind) > 0), -- pattern enforced by evidence.Decode
    tool_name        varchar(100),
    rule_id          varchar(500),
    template_digest  varchar(80),
    content          jsonb NOT NULL,
    content_sha256   varchar(80) NOT NULL,
    size_bytes       integer NOT NULL DEFAULT 0,
    truncated        boolean NOT NULL DEFAULT false,
    masked_count     integer NOT NULL DEFAULT 0,
    placeholders     text[] NOT NULL DEFAULT '{}',
    secrets_expire_at timestamptz,
    captured_at      timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_finding_evidence_content_size CHECK (pg_column_size(content) <= 400000),
    CONSTRAINT chk_finding_evidence_retest CHECK (origin <> 'retest' OR retest_id IS NOT NULL)
);

COMMENT ON TABLE finding_evidence IS
    'Masked proof per detection / retest attempt. Untrusted tool content: render as text only. Secrets live in finding_evidence_secrets.';

CREATE INDEX idx_finding_evidence_finding ON finding_evidence (tenant_id, finding_id, created_at DESC);
CREATE INDEX idx_finding_evidence_retest ON finding_evidence (retest_id) WHERE retest_id IS NOT NULL;
CREATE INDEX idx_finding_evidence_tenant_created ON finding_evidence (tenant_id, created_at);
CREATE INDEX idx_finding_evidence_created ON finding_evidence (created_at);

CREATE TABLE finding_evidence_secrets (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    evidence_id  uuid NOT NULL REFERENCES finding_evidence(id) ON DELETE CASCADE,
    placeholder  varchar(64) NOT NULL,
    secret_kind  varchar(32) NOT NULL,
    -- AES-256-GCM under APP_ENCRYPTION_KEY (re-keyed by cmd/rekey); the
    -- plaintext is bound to tenant, evidence and placeholder.
    ciphertext   text NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_finding_evidence_secret UNIQUE (evidence_id, placeholder)
);

COMMENT ON TABLE finding_evidence_secrets IS
    'Encrypted secret values masked out of finding_evidence. Read only by the audited reveal endpoint; deleted at expires_at.';

CREATE INDEX idx_finding_evidence_secrets_tenant ON finding_evidence_secrets (tenant_id, evidence_id);
CREATE INDEX idx_finding_evidence_secrets_expires ON finding_evidence_secrets (expires_at);

-- The reveal permission: owner and admin by default, assignable to custom roles.
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('findings:evidence:reveal', 'findings', 'Reveal Evidence Secrets', 'Reveal the masked secret values in finding evidence (step-up, audited)', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'findings:evidence:reveal'
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- A reveal is recorded on the finding's timeline.
ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened', 'assigned', 'unassigned',
    'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked', 'verified',
    'remediation_updated', 'metadata_updated', 'acceptance_expired', 'comment_added', 'comment_updated',
    'comment_deleted', 'scan_detected', 'auto_resolved', 'auto_reopened', 'linked', 'unlinked',
    'sla_warning', 'sla_breach', 'sla_restarted', 'ai_triage_requested', 'ai_triage', 'ai_triage_failed',
    'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled',
    'retest_requested', 'retest_completed', 'evidence_revealed'
)) NOT VALID;
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
