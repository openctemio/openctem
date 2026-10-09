-- Team membership expiry (RFC-050 W22, the team slice). A membership may end
-- on a date: an engagement team for a vendor, an audit team for an auditor,
-- a contractor on a project. The membership-expiry controller removes an
-- expired membership within a minute; removing it recomputes the member's
-- data scope (trigger group_members_scope_sync) and ends every other effect
-- of the team (notifications, campaign team).
ALTER TABLE group_members
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS expiry_reason VARCHAR(500);

COMMENT ON COLUMN group_members.expires_at IS
    'When the membership ends (NULL: no end). Removed by the membership-expiry controller within a minute.';
COMMENT ON COLUMN group_members.expiry_reason IS
    'Why the membership has an end date (engagement, audit period).';

CREATE INDEX IF NOT EXISTS idx_group_members_expires_at
    ON group_members (expires_at) WHERE expires_at IS NOT NULL;
