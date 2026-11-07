-- What a scan file's own coverage closed on an upload, and why the rest of
-- the findings it considered stayed open (docs/architecture/finding-import.md,
-- "What a Nessus import closes"). NULL: no file of the upload carried its
-- coverage. Adding a nullable column without a default rewrites no row.
ALTER TABLE ingest_receipts ADD COLUMN IF NOT EXISTS closing JSONB;
