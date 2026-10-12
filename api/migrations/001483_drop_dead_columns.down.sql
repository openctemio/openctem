-- Puts the columns back with their old types, defaults and comments.
-- Data that is not restored: users.federated_* (empty when 001483 ran; the
-- identities are in user_identities), admin_credentials.password_hash and
-- password_changed_at (unused stale values). event_types.default_severity is
-- restored from the seed values below; licenses get their old defaults.

ALTER TABLE sensors DROP CONSTRAINT chk_sensors_type;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_type
    CHECK (type IN ('worker', 'agent', 'scanner', 'collector', 'platform', 'sensor'));
ALTER TABLE sensors ALTER COLUMN type SET DEFAULT 'agent';

ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS is_osi_approved boolean DEFAULT false,
    ADD COLUMN IF NOT EXISTS is_fsf_libre boolean DEFAULT false,
    ADD COLUMN IF NOT EXISTS is_deprecated boolean DEFAULT false,
    ADD COLUMN IF NOT EXISTS limitations text[];

ALTER TABLE event_types ADD COLUMN IF NOT EXISTS default_severity character varying(20) DEFAULT 'info';
UPDATE event_types e SET default_severity = v.severity
  FROM (VALUES
    ('asset.created', 'info'), ('asset.exposure_changed', 'medium'), ('ci.break_glass', 'high'),
    ('ci.coverage_regression', 'high'), ('ci.gate_failing', 'medium'), ('ci.runner_outdated', 'medium'),
    ('ci.schedule_missed', 'high'), ('ci.token_refusals', 'high'), ('compliance_assessment_updated', 'info'),
    ('compliance_control_overdue', 'medium'), ('exposure.created', 'high'), ('finding.created', 'high'),
    ('finding.resolved', 'info'), ('finding.status_changed', 'info'), ('pentest_campaign_completed', 'info'),
    ('pentest_campaign_created', 'info'), ('pentest_finding_created', 'high'),
    ('pentest_finding_status_changed', 'info'), ('pentest_retest_completed', 'info'), ('scan.completed', 'info'),
    ('scan.failed', 'high'), ('scan.started', 'info'), ('sensor.error', 'medium'), ('sensor.offline', 'high')
  ) AS v(id, severity)
 WHERE e.id = v.id;

ALTER TABLE admin_credentials
    ADD COLUMN IF NOT EXISTS password_hash text,
    ADD COLUMN IF NOT EXISTS password_changed_at timestamp with time zone;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS members_without_group_see character varying(16) DEFAULT 'nothing' NOT NULL,
    ADD CONSTRAINT chk_tenants_members_without_group_see CHECK (members_without_group_see = 'nothing');
COMMENT ON COLUMN tenants.members_without_group_see IS 'Retired (owner decision D2, migration 000800): always nothing, no longer read. Members without a scope row see nothing in every organization. To be dropped after a release.';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS federated_issuer text,
    ADD COLUMN IF NOT EXISTS federated_subject text;
COMMENT ON COLUMN users.federated_issuer IS 'Deprecated: moved to user_identities (migration 001306); dropped in a later release.';
COMMENT ON COLUMN users.federated_subject IS 'Deprecated: moved to user_identities (migration 001306); dropped in a later release.';
