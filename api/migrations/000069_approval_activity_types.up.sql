-- Reconcile chk_activity_type constraint with all Go ActivityType constants.
--
-- Migration 000012 defined the original constraint with 16 types.
-- Since then, Go code added many new activity types that were never added to the constraint.
-- This migration drops and recreates the constraint to match exactly the 32 Go constants
-- defined in pkg/domain/vulnerability/finding_activity.go.
--
-- Data migration: 'accepted' was an ambiguous activity type (conflicts with finding status
-- name). Any existing rows are migrated to 'status_changed' which is the correct type.

-- Step 1: Drop old constraint
ALTER TABLE finding_activities DROP CONSTRAINT IF EXISTS chk_activity_type;

-- Step 2: Migrate legacy activity types that are being removed
UPDATE finding_activities SET activity_type = 'status_changed' WHERE activity_type = 'accepted';

-- Step 3: Add new constraint matching Go constants exactly (32 types)
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    -- Lifecycle
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened',

    -- Assignment
    'assigned', 'unassigned',

    -- Triage
    'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked',

    -- Verification & remediation
    'verified', 'remediation_updated', 'metadata_updated', 'acceptance_expired',

    -- Comment
    'comment_added', 'comment_updated', 'comment_deleted',

    -- Scanning
    'scan_detected', 'auto_resolved', 'auto_reopened',

    -- Integration
    'linked', 'unlinked',

    -- SLA
    'sla_warning', 'sla_breach',

    -- AI Triage
    'ai_triage_requested', 'ai_triage', 'ai_triage_failed',

    -- Approval
    'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled'
));
