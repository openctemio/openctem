package audit

// Configuration-change actions: settings and the resources around them that
// were changed without any audit record before (integrations, SCIM tokens,
// storage, rules). Each is written with a before/after diff
// (internal/app/audit.DiffChanges).
const (
	ActionInvitationResent Action = "invitation.resent"
	// ActionInvitationLinkRegenerated: an administrator copied a new link for
	// an invitation (the token rotated, nothing was emailed).
	ActionInvitationLinkRegenerated Action = "invitation.link_regenerated"
	// ActionInvitationRenewed: an expired invitation got a new lifetime and a
	// new link.
	ActionInvitationRenewed Action = "invitation.renewed"

	ActionSCIMTokenCreated Action = "scim_token.created"
	ActionSCIMTokenRevoked Action = "scim_token.revoked"
	ActionSCIMTokenRotated Action = "scim_token.rotated"

	ActionStorageConfigUpdated Action = "storage_config.updated"

	ActionIntegrationCreated              Action = "integration.created"
	ActionIntegrationUpdated              Action = "integration.updated"
	ActionIntegrationDeleted              Action = "integration.deleted"
	ActionIntegrationEnabled              Action = "integration.enabled"
	ActionIntegrationDisabled             Action = "integration.disabled"
	ActionIntegrationCredentialsChanged   Action = "integration.credentials_changed"
	ActionIntegrationWebhookSecretRead    Action = "integration.webhook_secret_read"
	ActionIntegrationWebhookSecretRotated Action = "integration.webhook_secret_rotated"
	// ActionIntegrationDeliveryRedelivered: an archived notification event
	// was queued again for one channel (RFC-124).
	ActionIntegrationDeliveryRedelivered Action = "integration.delivery_redelivered"

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

	ActionTicketMappingCreated   Action = "ticket_mapping.created"
	ActionTicketMappingUpdated   Action = "ticket_mapping.updated"
	ActionTicketMappingPublished Action = "ticket_mapping.published"
	ActionTicketMappingDeleted   Action = "ticket_mapping.deleted"

	ActionImportMappingCreated        Action = "import_mapping.created"
	ActionImportMappingVersionCreated Action = "import_mapping.version_created"
	ActionImportMappingUpdated        Action = "import_mapping.updated"
	ActionImportMappingDeleted        Action = "import_mapping.deleted"

	ActionTicketCreatePolicyUpdated Action = "ticket_create_policy.updated"
	// ActionTicketCreatedBelowThreshold: a person created an issue for a
	// finding below the integration's create policy (confirmed override).
	ActionTicketCreatedBelowThreshold Action = "ticket.created_below_threshold"
)

// Resource types for the configuration-change actions.
const (
	ResourceTypeSCIMToken          ResourceType = "scim_token"
	ResourceTypeStorageConfig      ResourceType = "storage_config"
	ResourceTypeNotificationOutbox ResourceType = "notification_outbox"
	ResourceTypePriorityRule       ResourceType = "priority_rule"
	ResourceTypeScopeRule          ResourceType = "scope_rule"
	ResourceTypeAssignmentRule     ResourceType = "assignment_rule"
	ResourceTypeTicketMapping      ResourceType = "ticket_mapping"
	ResourceTypeTicketCreatePolicy ResourceType = "ticket_create_policy"
	ResourceTypeImportMapping      ResourceType = "import_mapping"
)

var configActions = map[Action]struct{}{
	ActionInvitationResent:                {},
	ActionInvitationLinkRegenerated:       {},
	ActionInvitationRenewed:               {},
	ActionSCIMTokenCreated:                {},
	ActionSCIMTokenRevoked:                {},
	ActionSCIMTokenRotated:                {},
	ActionStorageConfigUpdated:            {},
	ActionIntegrationCreated:              {},
	ActionIntegrationUpdated:              {},
	ActionIntegrationDeleted:              {},
	ActionIntegrationEnabled:              {},
	ActionIntegrationDisabled:             {},
	ActionIntegrationCredentialsChanged:   {},
	ActionIntegrationWebhookSecretRead:    {},
	ActionIntegrationWebhookSecretRotated: {},
	ActionIntegrationDeliveryRedelivered:  {},
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
	ActionTicketMappingCreated:            {},
	ActionTicketMappingUpdated:            {},
	ActionTicketMappingPublished:          {},
	ActionTicketMappingDeleted:            {},
	ActionTicketCreatePolicyUpdated:       {},
	ActionImportMappingCreated:            {},
	ActionImportMappingVersionCreated:     {},
	ActionImportMappingUpdated:            {},
	ActionImportMappingDeleted:            {},
	ActionTicketCreatedBelowThreshold:     {},
}

var configResourceTypes = map[ResourceType]struct{}{
	ResourceTypeSCIMToken:          {},
	ResourceTypeStorageConfig:      {},
	ResourceTypeNotificationOutbox: {},
	ResourceTypePriorityRule:       {},
	ResourceTypeScopeRule:          {},
	ResourceTypeAssignmentRule:     {},
	ResourceTypeTicketMapping:      {},
	ResourceTypeTicketCreatePolicy: {},
	ResourceTypeImportMapping:      {},
	ResourceTypeDashboard:          {},
}

func isConfigAction(a Action) bool {
	_, ok := configActions[a]
	return ok
}

func isConfigResourceType(r ResourceType) bool {
	_, ok := configResourceTypes[r]
	return ok
}
