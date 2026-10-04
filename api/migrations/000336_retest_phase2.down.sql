DELETE FROM finding_activities WHERE activity_type = 'sla_restarted';

ALTER TABLE finding_activities DROP CONSTRAINT IF EXISTS chk_activity_type;
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened',
    'assigned', 'unassigned',
    'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked',
    'verified', 'remediation_updated', 'metadata_updated', 'acceptance_expired',
    'comment_added', 'comment_updated', 'comment_deleted',
    'scan_detected', 'auto_resolved', 'auto_reopened',
    'linked', 'unlinked',
    'sla_warning', 'sla_breach',
    'ai_triage_requested', 'ai_triage', 'ai_triage_failed',
    'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled',
    'retest_requested', 'retest_completed'
));

-- Proof-of-fix retests become auto retests so the narrowed check holds.
UPDATE finding_retests SET trigger = 'auto' WHERE trigger = 'proof_of_fix';
ALTER TABLE finding_retests DROP CONSTRAINT IF EXISTS chk_finding_retests_trigger;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_trigger
    CHECK (trigger IN ('manual', 'auto'));
