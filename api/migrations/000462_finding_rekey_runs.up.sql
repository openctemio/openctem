-- RFC-043 §6: re-fingerprint runs, one row per tenant.
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
--
-- The re-fingerprint job (cmd/refingerprint) re-keys a tenant's version-1
-- findings to the current identity recipe in batches. The row is its
-- checkpoint: cursor is the last finding id done, so an interrupted run
-- resumes where it stopped, and a finished run is a no-op (findings already
-- on the target version are skipped). While an applying run is in progress,
-- scan auto-resolve is paused for the tenant (decision D11): a finding whose
-- old key a scan did not produce must not be closed as fixed.

CREATE TABLE IF NOT EXISTS finding_rekey_runs (
    tenant_id      UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    target_version SMALLINT NOT NULL,
    status         VARCHAR(16) NOT NULL,
    cursor_id      UUID,
    rekeyed        INTEGER NOT NULL DEFAULT 0,
    merged         INTEGER NOT NULL DEFAULT 0,
    skipped        INTEGER NOT NULL DEFAULT 0,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at    TIMESTAMPTZ,
    CONSTRAINT chk_finding_rekey_runs_status CHECK (status IN ('running', 'completed')),
    CONSTRAINT chk_finding_rekey_runs_version CHECK (target_version >= 2),
    CONSTRAINT chk_finding_rekey_runs_counts CHECK (rekeyed >= 0 AND merged >= 0 AND skipped >= 0)
);

COMMENT ON TABLE finding_rekey_runs IS
    'Checkpoint of the per-tenant finding re-fingerprint job (RFC-043 §6). A running row pauses scan auto-resolve for the tenant (D11).';
