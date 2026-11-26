DROP TABLE IF EXISTS saml_connection_ids;
DROP INDEX IF EXISTS uq_saml_providers_legacy_path_key;
ALTER TABLE saml_providers DROP COLUMN IF EXISTS legacy_path_key;
