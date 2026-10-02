-- Intentional no-op. The up migration is purely additive (it only granted the
-- granular finding perms to roles that already held findings:write). On
-- rollback the routes revert to gating on findings:write, so the extra granular
-- grants become inert — harmless to leave in place. Removing them here would
-- risk stripping granular perms a role legitimately held BEFORE this migration
-- (e.g. owner/admin, which are seeded with the full granular set), since the
-- backfilled rows are indistinguishable from pre-existing ones. Leaving the
-- additive grants is the safe rollback.
SELECT 1;
