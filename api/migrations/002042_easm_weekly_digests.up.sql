-- Weekly "what changed" digest of the attack surface
-- (docs/rfcs/RFC-080-attack-surface-changes-and-digest.md). One row per
-- organization and digest slot: the insert is the claim, so a digest goes
-- out once per week however many API replicas run the controller.
CREATE TABLE easm_weekly_digests (
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slot       TIMESTAMPTZ NOT NULL,
    window_from TIMESTAMPTZ NOT NULL,
    total      INTEGER     NOT NULL DEFAULT 0,
    counts     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    sent_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_easm_weekly_digests PRIMARY KEY (tenant_id, slot),
    CONSTRAINT chk_easm_weekly_digests_window CHECK (window_from < slot),
    CONSTRAINT chk_easm_weekly_digests_total CHECK (total >= 0)
);
COMMENT ON TABLE easm_weekly_digests IS
    'RFC-080: one weekly attack-surface digest per organization and slot (claim + history of counts)';

-- Channels that already receive EASM alerts (new_exposure) also receive the
-- weekly digest; the per-integration event list stays the switch.
UPDATE integration_notification_extensions
   SET enabled_event_types = enabled_event_types || '["attack_surface_digest"]'::jsonb
 WHERE enabled_event_types ? 'new_exposure'
   AND NOT enabled_event_types ? 'attack_surface_digest';
