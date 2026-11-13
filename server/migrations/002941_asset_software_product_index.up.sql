-- Product folds (alias dictionary) repoint and delete by product: without an
-- index led by product_id each fold scans every tenant's links.
-- CONCURRENTLY keeps the table writable while it builds; it cannot run in a
-- transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_software_product_id ON asset_software (product_id);
