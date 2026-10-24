-- The machine code of an integration's last connection failure (the
-- INTEGRATION_* codes of pkg/apierror). The console words the failure from
-- it; status_message keeps a safe English sentence. Empty for rows written
-- before this column and for connected integrations.
-- Adding a column with a constant default is a metadata-only change.
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS status_code TEXT NOT NULL DEFAULT '';
