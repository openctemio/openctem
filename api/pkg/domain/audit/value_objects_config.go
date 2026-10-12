package audit

// Configuration-change actions: settings and the resources around them that
// were changed without any audit record before (integrations, SCIM tokens,
// storage, rules). Each is written with a before/after diff
// (internal/app/audit.DiffChanges).
const (
	ActionInvitationResent Action = "invitation.resent"

	ActionSCIMTokenCreated Action = "scim_token.created"
	ActionSCIMTokenRevoked Action = "scim_token.revoked"

	ActionStorageConfigUpdated Action = "storage_config.updated"

	ActionIntegrationCreated              Action = "integration.created"
	ActionIntegrationUpdated              Action = "integration.updated"
	ActionIntegrationDeleted              Action = "integration.deleted"
	ActionIntegrationEnabled              Action = "integration.enabled"
	ActionIntegrationDisabled             Action = "integration.disabled"
	ActionIntegrationCredentialsChanged   Action = "integration.credentials_changed"
	ActionIntegrationWebhookSecretRead    Action = "integration.webhook_secret_read"
	ActionIntegrationWebhookSecretRotated Action = "integration.webhook_secret_rotated"

	ActionNotificationOutboxRetried Action = "notification_outbox.retried"
	ActionNotificationOutboxDeleted Action = "notification_outbox.deleted"

	ActionPriorityRuleCreated Action = "priority_rule.created"
	ActionPriorityRuleUpdated Action = "priority_rule.updated"
	ActionPriorityRuleDeleted Action = "priority_rule.deleted"

	ActionScopeRuleCreated Action = "scope_rule.created"
	ActionScopeRuleUpdated Action = "scope_rule.updated"
	ActionScopeRuleDeleted Action = "scope_rule.deleted"

	ActionAssignmentRuleCreated Action = "assignment_rule.created"
	ActionAssignmentRuleUpdated Action = "assignment_rule.updated"
	ActionAssignmentRuleDeleted Action = "assignment_rule.deleted"
)

// Resource types for the configuration-change actions.
const (
	ResourceTypeSCIMToken          ResourceType = "scim_token"
	ResourceTypeStorageConfig      ResourceType = "storage_config"
	ResourceTypeNotificationOutbox ResourceType = "notification_outbox"
	ResourceTypePriorityRule       ResourceType = "priority_rule"
	ResourceTypeScopeRule          ResourceType = "scope_rule"
	ResourceTypeAssignmentRule     ResourceType = "assignment_rule"
)

var configActions = map[Action]struct{}{
	ActionInvitationResent:                {},
	ActionSCIMTokenCreated:                {},
	ActionSCIMTokenRevoked:                {},
	ActionStorageConfigUpdated:            {},
	ActionIntegrationCreated:              {},
	ActionIntegrationUpdated:              {},
	ActionIntegrationDeleted:              {},
	ActionIntegrationEnabled:              {},
	ActionIntegrationDisabled:             {},
	ActionIntegrationCredentialsChanged:   {},
	ActionIntegrationWebhookSecretRead:    {},
	ActionIntegrationWebhookSecretRotated: {},
	ActionNotificationOutboxRetried:       {},
	ActionNotificationOutboxDeleted:       {},
	ActionPriorityRuleCreated:             {},
	ActionPriorityRuleUpdated:             {},
	ActionPriorityRuleDeleted:             {},
	ActionScopeRuleCreated:                {},
	ActionScopeRuleUpdated:                {},
	ActionScopeRuleDeleted:                {},
	ActionAssignmentRuleCreated:           {},
	ActionAssignmentRuleUpdated:           {},
	ActionAssignmentRuleDeleted:           {},
}

var configResourceTypes = map[ResourceType]struct{}{
	ResourceTypeSCIMToken:          {},
	ResourceTypeStorageConfig:      {},
	ResourceTypeNotificationOutbox: {},
	ResourceTypePriorityRule:       {},
	ResourceTypeScopeRule:          {},
	ResourceTypeAssignmentRule:     {},
}

func isConfigAction(a Action) bool {
	_, ok := configActions[a]
	return ok
}

func isConfigResourceType(r ResourceType) bool {
	_, ok := configResourceTypes[r]
	return ok
}
