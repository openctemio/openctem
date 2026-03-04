-- Revert to original activity type constraint from migration 000012.

ALTER TABLE finding_activities DROP CONSTRAINT IF EXISTS chk_activity_type;

ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'assigned', 'unassigned',
    'comment_added', 'scan_detected', 'auto_resolved', 'auto_reopened',
    'duplicate_marked', 'duplicate_unmarked', 'accepted', 'acceptance_expired',
    'verified', 'remediation_updated', 'metadata_updated'
));
