-- Back to the fixed list of pages. Views of the other pages cannot be kept
-- by the older server (it refuses their keys), so they are removed.
DELETE FROM saved_views WHERE page NOT IN ('findings', 'vulnerabilities', 'assets', 'scans');
ALTER TABLE saved_views DROP CONSTRAINT IF EXISTS chk_saved_views_page;
ALTER TABLE saved_views ADD CONSTRAINT chk_saved_views_page
    CHECK (page IN ('findings', 'vulnerabilities', 'assets', 'scans'));
ALTER TABLE saved_views ALTER COLUMN page TYPE varchar(32);
COMMENT ON COLUMN saved_views.page IS NULL;
