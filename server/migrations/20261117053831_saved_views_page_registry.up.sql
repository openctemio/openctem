-- Saved views for every list page (docs/architecture/saved-views.md).
--
-- The pages that have views are a registry in the server
-- (pkg/domain/savedview/pages.go), which refuses a key it does not hold.
-- The table no longer lists the keys: it checks their shape only, so a new
-- list registers its key without a migration.
--
-- Live impact: saved_views is a small table (at most 100 rows per member).
-- Widening varchar(32) to varchar(64) does not rewrite the table, and the new
-- CHECK is validated in one pass; together they hold the table lock for a
-- fraction of a second on 50 000 rows. Every existing key (findings,
-- vulnerabilities, assets, scans) satisfies the new check.
--
-- expand-contract-ok: the type change only widens varchar(32) to varchar(64); a server of the previous release reads and writes the same values through the rollout
ALTER TABLE saved_views DROP CONSTRAINT IF EXISTS chk_saved_views_page;
ALTER TABLE saved_views ALTER COLUMN page TYPE varchar(64);
ALTER TABLE saved_views ADD CONSTRAINT chk_saved_views_page
    CHECK (page ~ $re$^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$$re$);

COMMENT ON COLUMN saved_views.page IS
    $c$Page key of the list the view belongs to: a key of the server page registry (pkg/domain/savedview/pages.go). The table checks the shape; the registry decides which keys exist and which permission reads each list.$c$;
