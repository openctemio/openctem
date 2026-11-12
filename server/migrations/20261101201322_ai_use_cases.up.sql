-- Per-use-case AI settings (docs/architecture/ai-use-cases.md): for each AI
-- use case (triage, remediation, summary) its mode (off, suggest,
-- auto_apply), the most sensitive data class it may send, the minimum
-- confidence to apply on its own, and the automatic downgrade state.
--
-- Stored with the organization's other AI settings, one JSON object keyed by
-- use case. {} means every use case at its default (suggest, internal, 0.85).
-- Adding a column with a constant default does not rewrite the table.
ALTER TABLE tenant_ai_settings
    ADD COLUMN IF NOT EXISTS use_cases jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE tenant_ai_settings
    ADD CONSTRAINT chk_tenant_ai_settings_use_cases_object CHECK (jsonb_typeof(use_cases) = 'object');

COMMENT ON COLUMN tenant_ai_settings.use_cases IS 'Per AI use case: mode (off, suggest, auto_apply), data class ceiling (public, internal, restricted), minimum confidence to auto-apply, automatic downgrade state; {} = every use case at its default (suggest, internal, 0.85).';
