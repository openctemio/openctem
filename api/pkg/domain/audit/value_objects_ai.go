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
)

var _ = registerActions("ai_settings", map[Action]Severity{
	ActionAISettingsUpdated:       SeverityCritical,
	ActionAISettingsTested:        SeverityLow,
	ActionAISettingsOptInMigrated: SeverityHigh,
})
