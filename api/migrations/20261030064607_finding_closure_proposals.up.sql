-- Ready to close: a close that the organization's closing mode or the tier
-- rule sends to a person instead of applying it
-- (docs/architecture/finding-verification-plan.md, "Ready to close").
-- One pending proposal per finding; the evaluator refreshes its evidence on
-- the next qualified scan. A person confirms (the finding closes as fixed)
-- or dismisses it with a reason; a sighting, or the finding leaving the open
-- statuses, cancels it.
CREATE TABLE finding_closure_proposals (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id   uuid        NOT NULL,
    method       text        NOT NULL,
    -- What proved it: command, run, tool, profile, template digest, sensor,
    -- whether the blinding guard held the run. Bounded by the writer.
    evidence     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    command_id   uuid,
    proposed_at  timestamptz NOT NULL DEFAULT now(),
    -- The latest qualified look that still did not see the finding.
    evidence_at  timestamptz NOT NULL DEFAULT now(),
    state        text        NOT NULL DEFAULT 'pending',
    decided_by   uuid        REFERENCES users(id) ON DELETE SET NULL,
    decided_at   timestamptz,
    reason       text        NOT NULL DEFAULT '',
    note         text        NOT NULL DEFAULT '',
    CONSTRAINT fk_finding_closure_proposals_finding
        FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_closure_proposals_method
        CHECK (method IN ('covered_scan', 'obsolete_asset', 'retest_verified', 'claimed_fix_scan', 'ci_default_branch', 'source_reported')),
    CONSTRAINT chk_finding_closure_proposals_state
        CHECK (state IN ('pending', 'confirmed', 'dismissed', 'canceled')),
    CONSTRAINT chk_finding_closure_proposals_reason
        CHECK (reason IN ('', 'still_present_manual_check', 'scan_not_trustworthy', 'wrong_asset', 'other',
                          'seen_again', 'status_changed')),
    CONSTRAINT chk_finding_closure_proposals_note CHECK (char_length(note) <= 1000),
    CONSTRAINT chk_finding_closure_proposals_decided
        CHECK ((state = 'pending') = (decided_at IS NULL))
);

CREATE UNIQUE INDEX uq_finding_closure_proposals_pending
    ON finding_closure_proposals (tenant_id, finding_id) WHERE state = 'pending';
CREATE INDEX idx_finding_closure_proposals_tenant_state
    ON finding_closure_proposals (tenant_id, state, proposed_at DESC);

COMMENT ON TABLE finding_closure_proposals IS 'Ready to close: closes a person confirms or dismisses (one pending per finding).';

CREATE POLICY finding_closure_proposals_tenant_isolation ON finding_closure_proposals
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
