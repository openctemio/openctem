-- Wire the lead auto-promotion DB trigger into the audit log so a cascade
-- delete (e.g., user removed from tenant) that promotes a tester to lead
-- leaves a paper trail. Without this, admins reviewing audit_logs see "user
-- deleted" then a mystery role change with no actor.

CREATE OR REPLACE FUNCTION check_campaign_lead_after_member_delete()
RETURNS TRIGGER AS $$
DECLARE
    promoted_member RECORD;
BEGIN
    IF OLD.role = 'lead' THEN
        IF NOT EXISTS (
            SELECT 1 FROM pentest_campaign_members
            WHERE campaign_id = OLD.campaign_id AND role = 'lead'
        ) THEN
            -- Promote oldest tester. Capture the row so we can audit it.
            UPDATE pentest_campaign_members
            SET role = 'lead'
            WHERE id = (
                SELECT id FROM pentest_campaign_members
                WHERE campaign_id = OLD.campaign_id AND role = 'tester'
                ORDER BY created_at ASC
                LIMIT 1
            )
            RETURNING * INTO promoted_member;

            -- If a tester was promoted, write an audit row with a system actor.
            -- actor_id = NULL signals "system" — admins know this is automated.
            IF promoted_member.id IS NOT NULL THEN
                INSERT INTO audit_logs (
                    tenant_id,
                    actor_id,
                    actor_email,
                    action,
                    resource_type,
                    resource_id,
                    result,
                    severity,
                    message,
                    metadata
                ) VALUES (
                    promoted_member.tenant_id,
                    NULL,
                    'system@auto-promote',
                    'campaign.member_role_changed',
                    'pentest_campaign',
                    promoted_member.campaign_id::text,
                    'success',
                    'high',
                    format('Auto-promoted user %s to lead after last lead %s was removed (cascade)',
                        promoted_member.user_id, OLD.user_id),
                    jsonb_build_object(
                        'member_user_id', promoted_member.user_id,
                        'previous_role', 'tester',
                        'new_role', 'lead',
                        'reason', 'cascade_last_lead_replacement',
                        'removed_lead_user_id', OLD.user_id,
                        'automated', true
                    )
                );
            END IF;
        END IF;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
