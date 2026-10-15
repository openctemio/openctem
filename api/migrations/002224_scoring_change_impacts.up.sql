-- One summary per scoring change instead of one alert per finding
-- (api/docs/architecture/scoring-versions.md, "No alert storms").
--
-- A finding-priority pass caused by a scoring change (a tenant's settings or
-- a new platform model) does not send one "priority escalated" notification
-- per finding. It adds its counts to the change's row here; when the change's
-- queue has drained, one summary notification is sent and notified_at is set.
--
-- Live impact: a new table.

CREATE TABLE IF NOT EXISTS scoring_change_impacts (
    scoring_change_id   bigint      NOT NULL,
    tenant_id           uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    findings_checked    integer     NOT NULL DEFAULT 0,
    findings_changed    integer     NOT NULL DEFAULT 0,
    findings_raised     integer     NOT NULL DEFAULT 0,
    raised_to_p0        integer     NOT NULL DEFAULT 0,
    findings_lowered    integer     NOT NULL DEFAULT 0,
    deadlines_tightened integer     NOT NULL DEFAULT 0,
    notified_at         timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_scoring_change_impacts PRIMARY KEY (tenant_id, scoring_change_id),
    CONSTRAINT fk_scoring_change_impacts_change FOREIGN KEY (scoring_change_id)
        REFERENCES scoring_changes (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scoring_change_impacts_pending
    ON scoring_change_impacts (updated_at) WHERE notified_at IS NULL;

COMMENT ON TABLE scoring_change_impacts IS
    'What a scoring change did to a tenant''s open findings, summed over the worker passes; one summary notification when notified_at is set.';

-- Channels that receive priority escalations also receive the summary that
-- replaces them for scoring changes; the per-integration event list stays
-- the switch.
UPDATE integration_notification_extensions
   SET enabled_event_types = enabled_event_types || '["scoring_change_applied"]'::jsonb
 WHERE enabled_event_types ? 'finding_priority_escalated'
   AND NOT enabled_event_types ? 'scoring_change_applied';
