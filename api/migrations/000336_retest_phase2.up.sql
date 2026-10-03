-- RFC-039 Phase 2.
--
-- 1. finding_retests.trigger gains 'proof_of_fix': a finding marked
--    fix_applied (by a person or by Jira "Done") is retested automatically —
--    the finding's own template plus a reachability probe — instead of the
--    retired whole-asset "verification scan" (owner decision D4).
-- 2. finding_activities gains 'sla_restarted': a regression gets a fresh SLA
--    deadline from the reopen, and the reason and the previous deadline are
--    recorded (owner decision D2).

ALTER TABLE finding_retests DROP CONSTRAINT IF EXISTS chk_finding_retests_trigger;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_trigger
    CHECK (trigger IN ('manual', 'auto', 'proof_of_fix'));

ALTER TABLE finding_activities DROP CONSTRAINT IF EXISTS chk_activity_type;
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened',
    'assigned', 'unassigned',
    'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked',
    'verified', 'remediation_updated', 'metadata_updated', 'acceptance_expired',
    'comment_added', 'comment_updated', 'comment_deleted',
    'scan_detected', 'auto_resolved', 'auto_reopened',
    'linked', 'unlinked',
    'sla_warning', 'sla_breach', 'sla_restarted',
    'ai_triage_requested', 'ai_triage', 'ai_triage_failed',
    'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled',
    'retest_requested', 'retest_completed'
));
