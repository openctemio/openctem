DELETE FROM saved_views WHERE page IN ('assets', 'scans');
ALTER TABLE saved_views DROP CONSTRAINT IF EXISTS chk_saved_views_page;
ALTER TABLE saved_views ADD CONSTRAINT chk_saved_views_page
    CHECK (page IN ('findings', 'vulnerabilities'));
