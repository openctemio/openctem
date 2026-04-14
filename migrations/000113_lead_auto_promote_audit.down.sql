-- Restore the original trigger function (no audit logging).
CREATE OR REPLACE FUNCTION check_campaign_lead_after_member_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.role = 'lead' THEN
        IF NOT EXISTS (
            SELECT 1 FROM pentest_campaign_members
            WHERE campaign_id = OLD.campaign_id AND role = 'lead'
        ) THEN
            UPDATE pentest_campaign_members
            SET role = 'lead'
            WHERE id = (
                SELECT id FROM pentest_campaign_members
                WHERE campaign_id = OLD.campaign_id AND role = 'tester'
                ORDER BY created_at ASC
                LIMIT 1
            );
        END IF;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
