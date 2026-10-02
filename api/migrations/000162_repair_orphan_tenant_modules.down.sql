-- Deliberate no-op. The repair cascaded disables to match the
-- dependency graph; reverting would require an audit trail of which
-- disables were "natural" vs "cascade". Admins can re-enable any
-- module via Settings → Modules after the down-migration runs.
BEGIN;
COMMIT;
