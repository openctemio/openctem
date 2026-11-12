-- Re-attestation of long intrusive (t2) scope entries (RFC-054 §12.5): an
-- active t2 entry is confirmed every t2_attestation_days, or it falls back to
-- t1 after a 14-day grace. Nullable columns: existing entries start their
-- first period from their approval.

ALTER TABLE scope_targets
    ADD COLUMN IF NOT EXISTS attested_at              timestamptz  NULL,
    ADD COLUMN IF NOT EXISTS attested_by              varchar(200) NULL,
    ADD COLUMN IF NOT EXISTS attestation_requested_at timestamptz  NULL;

-- The attestation job reads the active t2 entries.
CREATE INDEX IF NOT EXISTS idx_scope_targets_active_t2
    ON scope_targets (tenant_id) WHERE max_tier = 2 AND status = 'active';

COMMENT ON COLUMN scope_targets.attested_at IS 'Last confirmation that this t2 entry keeps intrusive probes (RFC-054 §12.5)';
COMMENT ON COLUMN scope_targets.attestation_requested_at IS 'Open attestation request; unanswered for 14 days the entry falls back to t1';
