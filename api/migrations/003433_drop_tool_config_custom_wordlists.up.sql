-- tenant_tool_configs.custom_wordlists was never read by anything: wordlists
-- are content packs of kind 'wordlist' (docs/architecture/content-packs.md).
ALTER TABLE tenant_tool_configs DROP COLUMN IF EXISTS custom_wordlists;
