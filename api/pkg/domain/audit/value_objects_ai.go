package audit

// AI triage organization settings (docs/architecture/ai-triage.md).

const (
	// ActionAISettingsUpdated records an organization administrator turning
	// AI triage on (consent to send finding content to the AI provider) or
	// off.
	ActionAISettingsUpdated Action = "ai_settings.updated"
	// ActionAISettingsTested records a "test connection" of the organization's
	// own AI provider (no finding data is sent).
	ActionAISettingsTested Action = "ai_settings.tested"
	// ActionAISettingsOptInMigrated records the upgrade keeping AI triage on
	// for an organization that already used it before consent existed.
	ActionAISettingsOptInMigrated Action = "ai_settings.opt_in_migrated"
	// ActionAIMaskingUpdated records a change of the organization's AI
	// masking policy (docs/architecture/ai-context-masking.md); a change that
	// masks less is flagged in the metadata.
	ActionAIMaskingUpdated Action = "ai_settings.masking_updated"
	// ActionAIMaskingPreviewed records an administrator previewing the masked
	// context the AI would get for one finding.
	ActionAIMaskingPreviewed Action = "ai_settings.masking_previewed"
)

var _ = registerActions("ai_settings", map[Action]Severity{
	ActionAISettingsUpdated:       SeverityCritical,
	ActionAISettingsTested:        SeverityLow,
	ActionAISettingsOptInMigrated: SeverityHigh,
	ActionAIMaskingUpdated:        SeverityHigh,
	ActionAIMaskingPreviewed:      SeverityLow,
})
