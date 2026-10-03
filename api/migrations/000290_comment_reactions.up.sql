-- Emoji reactions on finding comments, and internal (organization-only)
-- comments.
--
-- comment_reactions: one row per (comment, user, emoji). The tenant is stored
-- so every read and write can be tenant-scoped without joining back to the
-- comment; a trigger keeps it equal to the comment's tenant, the same way
-- 000159 ties finding_comments.tenant_id to the finding.

BEGIN;

ALTER TABLE finding_comments
    ADD COLUMN IF NOT EXISTS is_internal BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN finding_comments.is_internal IS
    'Organization-only comment: never sent to an integration, ticket or notifier outside the tenant';

CREATE TABLE IF NOT EXISTS comment_reactions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    comment_id UUID NOT NULL REFERENCES finding_comments(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT comment_reactions_unique UNIQUE (comment_id, user_id, emoji),
    CONSTRAINT comment_reactions_emoji_len CHECK (octet_length(emoji) BETWEEN 1 AND 32)
);

COMMENT ON TABLE comment_reactions IS 'Emoji reactions on finding comments';

CREATE INDEX IF NOT EXISTS idx_comment_reactions_comment_id
    ON comment_reactions(comment_id);
CREATE INDEX IF NOT EXISTS idx_comment_reactions_tenant_id
    ON comment_reactions(tenant_id);

CREATE OR REPLACE FUNCTION comment_reaction_tenant_matches_comment() RETURNS TRIGGER AS $$
DECLARE
    parent_tenant UUID;
BEGIN
    SELECT tenant_id INTO parent_tenant FROM finding_comments WHERE id = NEW.comment_id;
    IF parent_tenant IS NULL THEN
        RAISE EXCEPTION 'comment % not found', NEW.comment_id;
    END IF;
    IF NEW.tenant_id <> parent_tenant THEN
        RAISE EXCEPTION 'tenant_id mismatch: reaction tenant % != comment tenant %',
            NEW.tenant_id, parent_tenant;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_comment_reaction_tenant_match ON comment_reactions;
CREATE TRIGGER trg_comment_reaction_tenant_match
    BEFORE INSERT OR UPDATE ON comment_reactions
    FOR EACH ROW
    EXECUTE FUNCTION comment_reaction_tenant_matches_comment();

COMMIT;
