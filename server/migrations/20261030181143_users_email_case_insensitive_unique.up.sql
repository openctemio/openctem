-- One account per mailbox whatever the case: addresses differing only in case
-- name the same mailbox, so users.email is unique on lower(email). Lookups
-- compare lower(email) = lower($1) and use this index; the application stores
-- new and changed addresses trimmed and lower-cased.
--
-- Fails with a clear message, and changes nothing, when two accounts already
-- hold the same address in different case: merge or rename them first.
DO $$
DECLARE
    dup_groups integer;
BEGIN
    SELECT count(*) INTO dup_groups
    FROM (SELECT 1 FROM users GROUP BY lower(email) HAVING count(*) > 1) d;
    IF dup_groups > 0 THEN
        RAISE EXCEPTION 'users_email_case_insensitive_unique: % address(es) are held by more than one account in different case; resolve them before upgrading (SELECT lower(email), count(*) FROM users GROUP BY 1 HAVING count(*) > 1)', dup_groups;
    END IF;
END
$$;

CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email));
