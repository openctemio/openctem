DROP TRIGGER IF EXISTS trg_findings_sla_deadline_tightened ON findings;
DROP FUNCTION IF EXISTS record_sla_deadline_tightened();
DELETE FROM finding_activities WHERE activity_type = 'sla_deadline_tightened';
ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened', 'assigned', 'unassigned', 'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked', 'verified', 'remediation_updated', 'metadata_updated', 'acceptance_expired', 'comment_added', 'comment_updated', 'comment_deleted', 'scan_detected', 'auto_resolved', 'auto_reopened', 'linked', 'unlinked', 'sla_warning', 'sla_breach', 'sla_restarted', 'ai_triage_requested', 'ai_triage', 'ai_triage_failed', 'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled', 'retest_requested', 'retest_completed', 'evidence_revealed',
    'decision_review'));
