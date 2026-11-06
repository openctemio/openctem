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
	// ActionAIAutoTriageUpdated records a change of the organization's
	// automatic AI triage policy; a loosening (on, more severities) is
	// audited high and flagged in the metadata.
	ActionAIAutoTriageUpdated Action = "ai_settings.auto_triage_updated"
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
	ActionAIAutoTriageUpdated:     SeverityMedium,
})

// Per-use-case AI settings (docs/architecture/ai-use-cases.md).
const (
	// ActionAIUseCaseUpdated records a change of one AI use case's mode,
	// data class ceiling or minimum confidence. A loosening (auto-apply on,
	// ceiling above internal, lower confidence while auto-applying) is
	// audited critical.
	ActionAIUseCaseUpdated Action = "ai_use_case.updated"
	// ActionAIUseCaseDowngraded records the automatic fall-back of a use
	// case from auto-apply to suggest, after people overrode its results.
	ActionAIUseCaseDowngraded Action = "ai_use_case.downgraded"
)

var _ = registerActions("ai_use_case", map[Action]Severity{
	ActionAIUseCaseUpdated:    SeverityMedium,
	ActionAIUseCaseDowngraded: SeverityHigh,
})
