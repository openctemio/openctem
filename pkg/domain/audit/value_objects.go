package audit

import "fmt"

// Action represents the type of action performed.
type Action string

const (
	// User actions
	ActionUserCreated     Action = "user.created"
	ActionUserUpdated     Action = "user.updated"
	ActionUserDeleted     Action = "user.deleted"
	ActionUserSuspended   Action = "user.suspended"
	ActionUserActivated   Action = "user.activated"
	ActionUserDeactivated Action = "user.deactivated"
	ActionUserLogin       Action = "user.login"
	ActionUserLogout      Action = "user.logout"

	// Tenant actions
	ActionTenantCreated         Action = "tenant.created"
	ActionTenantUpdated         Action = "tenant.updated"
	ActionTenantDeleted         Action = "tenant.deleted"
	ActionTenantSettingsUpdated Action = "tenant.settings_updated"

	// Membership actions
	ActionMemberAdded       Action = "member.added"
	ActionMemberRemoved     Action = "member.removed"
	ActionMemberRoleChanged Action = "member.role_changed"

	// Invitation actions
	ActionInvitationCreated  Action = "invitation.created"
	ActionInvitationAccepted Action = "invitation.accepted"
	ActionInvitationDeleted  Action = "invitation.deleted"
	ActionInvitationExpired  Action = "invitation.expired"

	// Repository actions
	ActionRepositoryCreated  Action = "repository.created"
	ActionRepositoryUpdated  Action = "repository.updated"
	ActionRepositoryDeleted  Action = "repository.deleted"
	ActionRepositoryArchived Action = "repository.archived"

	// Component actions
	ActionComponentCreated Action = "component.created"
	ActionComponentUpdated Action = "component.updated"
	ActionComponentDeleted Action = "component.deleted"

	// Vulnerability actions
	ActionVulnerabilityCreated Action = "vulnerability.created"
	ActionVulnerabilityUpdated Action = "vulnerability.updated"
	ActionVulnerabilityDeleted Action = "vulnerability.deleted"

	// Finding actions
	ActionFindingCreated       Action = "finding.created"
	ActionFindingUpdated       Action = "finding.updated"
	ActionFindingDeleted       Action = "finding.deleted"
	ActionFindingStatusChanged Action = "finding.status_changed"
	ActionFindingTriaged       Action = "finding.triaged"
	ActionFindingAssigned      Action = "finding.assigned"
	ActionFindingUnassigned    Action = "finding.unassigned"
	ActionFindingCommented     Action = "finding.commented"
	ActionFindingBulkUpdated   Action = "finding.bulk_updated"

	// Branch actions
	ActionBranchCreated    Action = "branch.created"
	ActionBranchUpdated    Action = "branch.updated"
	ActionBranchDeleted    Action = "branch.deleted"
	ActionBranchScanned    Action = "branch.scanned"
	ActionBranchSetDefault Action = "branch.set_default"

	// SLA Policy actions
	ActionSLAPolicyCreated Action = "sla_policy.created"
	ActionSLAPolicyUpdated Action = "sla_policy.updated"
	ActionSLAPolicyDeleted Action = "sla_policy.deleted"

	// Scan actions
	ActionScanStarted   Action = "scan.started"
	ActionScanCompleted Action = "scan.completed"
	ActionScanFailed    Action = "scan.failed"

	// Security actions
	ActionAuthLogin        Action = "auth.login"
	ActionAuthLogout       Action = "auth.logout"
	ActionAuthRegister     Action = "auth.register"
	ActionAuthFailed       Action = "auth.failed"
	ActionPermissionDenied Action = "permission.denied"
	ActionTokenRevoked     Action = "token.revoked"

	// Settings actions
	ActionSettingsUpdated Action = "settings.updated"

	// Data actions
	ActionDataExported Action = "data.exported"
	ActionDataImported Action = "data.imported"

	// Agent actions
	ActionAgentCreated        Action = "agent.created"
	ActionAgentUpdated        Action = "agent.updated"
	ActionAgentDeleted        Action = "agent.deleted"
	ActionAgentActivated      Action = "agent.activated"
	ActionAgentDeactivated    Action = "agent.deactivated"
	ActionAgentRevoked        Action = "agent.revoked"
	ActionAgentKeyRegenerated Action = "agent.key_regenerated"
	ActionAgentConnected      Action = "agent.connected"
	ActionAgentDisconnected   Action = "agent.disconnected"

	// Credential (Secret Store) actions
	ActionCredentialCreated  Action = "credential.created"
	ActionCredentialUpdated  Action = "credential.updated"
	ActionCredentialDeleted  Action = "credential.deleted"
	ActionCredentialAccessed Action = "credential.accessed"

	// Group actions
	ActionGroupCreated Action = "group.created"
	ActionGroupUpdated Action = "group.updated"
	ActionGroupDeleted Action = "group.deleted"

	// Capability actions
	ActionCapabilityCreated Action = "capability.created"
	ActionCapabilityUpdated Action = "capability.updated"
	ActionCapabilityDeleted Action = "capability.deleted"

	// Tool actions
	ActionToolCreated         Action = "tool.created"
	ActionToolUpdated         Action = "tool.updated"
	ActionToolDeleted         Action = "tool.deleted"
	ActionToolCapabilitiesSet Action = "tool.capabilities_set"

	// Asset Ownership actions
	ActionAssetAssigned         Action = "asset.assigned"
	ActionAssetUnassigned       Action = "asset.unassigned"
	ActionAssetOwnershipUpdated Action = "asset.ownership_updated"

	// Permission Set actions
	ActionPermissionSetCreated    Action = "permission_set.created"
	ActionPermissionSetUpdated    Action = "permission_set.updated"
	ActionPermissionSetDeleted    Action = "permission_set.deleted"
	ActionPermissionSetAssigned   Action = "permission_set.assigned"
	ActionPermissionSetUnassigned Action = "permission_set.unassigned"

	// Permission actions
	ActionPermissionGranted Action = "permission.granted"
	ActionPermissionRevoked Action = "permission.revoked"

	// Role actions
	ActionRoleCreated      Action = "role.created"
	ActionRoleUpdated      Action = "role.updated"
	ActionRoleDeleted      Action = "role.deleted"
	ActionRoleAssigned     Action = "role.assigned"
	ActionRoleUnassigned   Action = "role.unassigned"
	ActionUserRolesUpdated Action = "user.roles_updated"

	// Pipeline actions
	ActionPipelineTemplateCreated     Action = "pipeline_template.created"
	ActionPipelineTemplateUpdated     Action = "pipeline_template.updated"
	ActionPipelineTemplateDeleted     Action = "pipeline_template.deleted"
	ActionPipelineTemplateActivated   Action = "pipeline_template.activated"
	ActionPipelineTemplateDeactivated Action = "pipeline_template.deactivated"
	ActionPipelineStepCreated         Action = "pipeline_step.created"
	ActionPipelineStepUpdated         Action = "pipeline_step.updated"
	ActionPipelineStepDeleted         Action = "pipeline_step.deleted"
	ActionPipelineRunTriggered        Action = "pipeline_run.triggered"
	ActionPipelineRunCompleted        Action = "pipeline_run.completed"
	ActionPipelineRunFailed           Action = "pipeline_run.failed"
	ActionPipelineRunCancelled        Action = "pipeline_run.cancelled"

	// Scan config actions
	ActionScanConfigCreated   Action = "scan_config.created"
	ActionScanConfigUpdated   Action = "scan_config.updated"
	ActionScanConfigDeleted   Action = "scan_config.deleted"
	ActionScanConfigTriggered Action = "scan_config.triggered"
	ActionScanConfigPaused    Action = "scan_config.paused"
	ActionScanConfigActivated Action = "scan_config.activated"
	ActionScanConfigDisabled  Action = "scan_config.disabled"

	// Security events
	ActionSecurityValidationFailed  Action = "security.validation_failed"
	ActionSecurityCrossTenantAccess Action = "security.cross_tenant_access"

	// Workflow actions
	ActionWorkflowCreated      Action = "workflow.created"
	ActionWorkflowUpdated      Action = "workflow.updated"
	ActionWorkflowDeleted      Action = "workflow.deleted"
	ActionWorkflowActivated    Action = "workflow.activated"
	ActionWorkflowDeactivated  Action = "workflow.deactivated"
	ActionWorkflowRunTriggered Action = "workflow_run.triggered"
	ActionWorkflowRunCompleted Action = "workflow_run.completed"
	ActionWorkflowRunFailed    Action = "workflow_run.failed"
	ActionWorkflowRunCancelled Action = "workflow_run.cancelled"

	// Rule actions
	ActionRuleSourceCreated   Action = "rule_source.created"
	ActionRuleSourceUpdated   Action = "rule_source.updated"
	ActionRuleSourceDeleted   Action = "rule_source.deleted"
	ActionRuleOverrideCreated Action = "rule_override.created"
	ActionRuleOverrideUpdated Action = "rule_override.updated"
	ActionRuleOverrideDeleted Action = "rule_override.deleted"

	// Ingest actions (agent upload)
	ActionIngestStarted        Action = "ingest.started"
	ActionIngestCompleted      Action = "ingest.completed"
	ActionIngestFailed         Action = "ingest.failed"
	ActionIngestPartialSuccess Action = "ingest.partial_success"

	// AI Triage actions
	ActionAITriageRequested  Action = "ai_triage.requested"
	ActionAITriageStarted    Action = "ai_triage.started"
	ActionAITriageCompleted  Action = "ai_triage.completed"
	ActionAITriageFailed     Action = "ai_triage.failed"
	ActionAITriageBulk       Action = "ai_triage.bulk_requested"
	ActionAITriageRateLimit  Action = "ai_triage.rate_limited"
	ActionAITriageTokenLimit Action = "ai_triage.token_limit_exceeded"
)

// String returns the string representation of the action.
func (a Action) String() string {
	return string(a)
}

// IsValid checks if the action is a known action type.
func (a Action) IsValid() bool {
	switch a {
	case ActionUserCreated, ActionUserUpdated, ActionUserDeleted,
		ActionUserSuspended, ActionUserActivated, ActionUserDeactivated,
		ActionUserLogin, ActionUserLogout,
		ActionTenantCreated, ActionTenantUpdated, ActionTenantDeleted, ActionTenantSettingsUpdated,
		ActionMemberAdded, ActionMemberRemoved, ActionMemberRoleChanged,
		ActionInvitationCreated, ActionInvitationAccepted, ActionInvitationDeleted, ActionInvitationExpired,
		ActionRepositoryCreated, ActionRepositoryUpdated, ActionRepositoryDeleted, ActionRepositoryArchived,
		ActionComponentCreated, ActionComponentUpdated, ActionComponentDeleted,
		ActionVulnerabilityCreated, ActionVulnerabilityUpdated, ActionVulnerabilityDeleted,
		ActionFindingCreated, ActionFindingUpdated, ActionFindingDeleted, ActionFindingStatusChanged,
		ActionFindingTriaged, ActionFindingAssigned, ActionFindingUnassigned, ActionFindingCommented, ActionFindingBulkUpdated,
		ActionBranchCreated, ActionBranchUpdated, ActionBranchDeleted, ActionBranchScanned, ActionBranchSetDefault,
		ActionSLAPolicyCreated, ActionSLAPolicyUpdated, ActionSLAPolicyDeleted,
		ActionScanStarted, ActionScanCompleted, ActionScanFailed,
		ActionAuthLogin, ActionAuthLogout, ActionAuthRegister, ActionAuthFailed, ActionPermissionDenied, ActionTokenRevoked,
		ActionSettingsUpdated, ActionDataExported, ActionDataImported,
		ActionAgentCreated, ActionAgentUpdated, ActionAgentDeleted,
		ActionAgentActivated, ActionAgentDeactivated, ActionAgentRevoked,
		ActionAgentKeyRegenerated, ActionAgentConnected, ActionAgentDisconnected,
		ActionGroupCreated, ActionGroupUpdated, ActionGroupDeleted,
		ActionCapabilityCreated, ActionCapabilityUpdated, ActionCapabilityDeleted,
		ActionToolCreated, ActionToolUpdated, ActionToolDeleted, ActionToolCapabilitiesSet,
		ActionAssetAssigned, ActionAssetUnassigned, ActionAssetOwnershipUpdated,
		ActionPermissionSetCreated, ActionPermissionSetUpdated, ActionPermissionSetDeleted,
		ActionPermissionSetAssigned, ActionPermissionSetUnassigned,
		ActionPermissionGranted, ActionPermissionRevoked,
		ActionRoleCreated, ActionRoleUpdated, ActionRoleDeleted,
		ActionRoleAssigned, ActionRoleUnassigned, ActionUserRolesUpdated,
		ActionPipelineTemplateCreated, ActionPipelineTemplateUpdated, ActionPipelineTemplateDeleted,
		ActionPipelineTemplateActivated, ActionPipelineTemplateDeactivated,
		ActionPipelineStepCreated, ActionPipelineStepUpdated, ActionPipelineStepDeleted,
		ActionPipelineRunTriggered, ActionPipelineRunCompleted, ActionPipelineRunFailed, ActionPipelineRunCancelled,
		ActionScanConfigCreated, ActionScanConfigUpdated, ActionScanConfigDeleted, ActionScanConfigTriggered,
		ActionScanConfigPaused, ActionScanConfigActivated, ActionScanConfigDisabled,
		ActionSecurityValidationFailed, ActionSecurityCrossTenantAccess,
		ActionWorkflowCreated, ActionWorkflowUpdated, ActionWorkflowDeleted,
		ActionWorkflowActivated, ActionWorkflowDeactivated,
		ActionWorkflowRunTriggered, ActionWorkflowRunCompleted, ActionWorkflowRunFailed, ActionWorkflowRunCancelled,
		ActionRuleSourceCreated, ActionRuleSourceUpdated, ActionRuleSourceDeleted,
		ActionRuleOverrideCreated, ActionRuleOverrideUpdated, ActionRuleOverrideDeleted,
		ActionIngestStarted, ActionIngestCompleted, ActionIngestFailed, ActionIngestPartialSuccess,
		ActionAITriageRequested, ActionAITriageStarted, ActionAITriageCompleted, ActionAITriageFailed,
		ActionAITriageBulk, ActionAITriageRateLimit, ActionAITriageTokenLimit:
		return true
	}
	return false
}

// Category returns the category of the action (e.g., "user", "tenant").
func (a Action) Category() string {
	switch a {
	case ActionUserCreated, ActionUserUpdated, ActionUserDeleted,
		ActionUserSuspended, ActionUserActivated, ActionUserDeactivated,
		ActionUserLogin, ActionUserLogout:
		return "user"
	case ActionTenantCreated, ActionTenantUpdated, ActionTenantDeleted, ActionTenantSettingsUpdated:
		return "tenant"
	case ActionMemberAdded, ActionMemberRemoved, ActionMemberRoleChanged:
		return "member"
	case ActionInvitationCreated, ActionInvitationAccepted, ActionInvitationDeleted, ActionInvitationExpired:
		return "invitation"
	case ActionRepositoryCreated, ActionRepositoryUpdated, ActionRepositoryDeleted, ActionRepositoryArchived:
		return "repository"
	case ActionBranchCreated, ActionBranchUpdated, ActionBranchDeleted, ActionBranchScanned, ActionBranchSetDefault:
		return "branch"
	case ActionComponentCreated, ActionComponentUpdated, ActionComponentDeleted:
		return "component"
	case ActionVulnerabilityCreated, ActionVulnerabilityUpdated, ActionVulnerabilityDeleted:
		return "vulnerability"
	case ActionFindingCreated, ActionFindingUpdated, ActionFindingDeleted, ActionFindingStatusChanged,
		ActionFindingTriaged, ActionFindingAssigned, ActionFindingUnassigned, ActionFindingCommented, ActionFindingBulkUpdated:
		return "finding"
	case ActionSLAPolicyCreated, ActionSLAPolicyUpdated, ActionSLAPolicyDeleted:
		return "sla_policy"
	case ActionScanStarted, ActionScanCompleted, ActionScanFailed:
		return "scan"
	case ActionAuthLogin, ActionAuthLogout, ActionAuthRegister, ActionAuthFailed, ActionPermissionDenied, ActionTokenRevoked:
		return "security"
	case ActionSettingsUpdated:
		return "settings"
	case ActionDataExported, ActionDataImported:
		return "data"
	case ActionAgentCreated, ActionAgentUpdated, ActionAgentDeleted,
		ActionAgentActivated, ActionAgentDeactivated, ActionAgentRevoked,
		ActionAgentKeyRegenerated, ActionAgentConnected, ActionAgentDisconnected:
		return "agent"
	case ActionCapabilityCreated, ActionCapabilityUpdated, ActionCapabilityDeleted:
		return "capability"
	case ActionToolCreated, ActionToolUpdated, ActionToolDeleted, ActionToolCapabilitiesSet:
		return "tool"
	case ActionRuleSourceCreated, ActionRuleSourceUpdated, ActionRuleSourceDeleted,
		ActionRuleOverrideCreated, ActionRuleOverrideUpdated, ActionRuleOverrideDeleted:
		return "rule"
	case ActionIngestStarted, ActionIngestCompleted, ActionIngestFailed, ActionIngestPartialSuccess:
		return "ingest"
	case ActionAITriageRequested, ActionAITriageStarted, ActionAITriageCompleted, ActionAITriageFailed,
		ActionAITriageBulk, ActionAITriageRateLimit, ActionAITriageTokenLimit:
		return "ai_triage"
	}
	return "unknown"
}

// ResourceType represents the type of resource being acted upon.
type ResourceType string

const (
	ResourceTypeUser             ResourceType = "user"
	ResourceTypeTenant           ResourceType = "tenant"
	ResourceTypeMembership       ResourceType = "membership"
	ResourceTypeInvitation       ResourceType = "invitation"
	ResourceTypeRepository       ResourceType = "repository"
	ResourceTypeBranch           ResourceType = "branch"
	ResourceTypeComponent        ResourceType = "component"
	ResourceTypeVulnerability    ResourceType = "vulnerability"
	ResourceTypeFinding          ResourceType = "finding"
	ResourceTypeFindingComment   ResourceType = "finding_comment"
	ResourceTypeSLAPolicy        ResourceType = "sla_policy"
	ResourceTypeScan             ResourceType = "scan"
	ResourceTypeAsset            ResourceType = "asset"
	ResourceTypeSettings         ResourceType = "settings"
	ResourceTypeToken            ResourceType = "token"
	ResourceTypeAgent            ResourceType = "agent"
	ResourceTypeGroup            ResourceType = "group"
	ResourceTypePermissionSet    ResourceType = "permission_set"
	ResourceTypeRole             ResourceType = "role"
	ResourceTypePipelineTemplate ResourceType = "pipeline_template"
	ResourceTypePipelineStep     ResourceType = "pipeline_step"
	ResourceTypePipelineRun      ResourceType = "pipeline_run"
	ResourceTypeScanConfig       ResourceType = "scan_config"
	ResourceTypeWorkflow         ResourceType = "workflow"
	ResourceTypeWorkflowRun      ResourceType = "workflow_run"
	ResourceTypeCapability       ResourceType = "capability"
	ResourceTypeTool             ResourceType = "tool"
	ResourceTypeRuleSource       ResourceType = "rule_source"
	ResourceTypeRuleOverride     ResourceType = "rule_override"
	ResourceTypeIngest           ResourceType = "ingest"
	ResourceTypeAITriage         ResourceType = "ai_triage"
)

// String returns the string representation of the resource type.
func (r ResourceType) String() string {
	return string(r)
}

// IsValid checks if the resource type is valid.
func (r ResourceType) IsValid() bool {
	switch r {
	case ResourceTypeUser, ResourceTypeTenant, ResourceTypeMembership,
		ResourceTypeInvitation, ResourceTypeRepository, ResourceTypeBranch,
		ResourceTypeComponent, ResourceTypeVulnerability, ResourceTypeFinding,
		ResourceTypeFindingComment, ResourceTypeSLAPolicy, ResourceTypeScan,
		ResourceTypeAsset, ResourceTypeSettings, ResourceTypeToken, ResourceTypeAgent,
		ResourceTypeGroup, ResourceTypePermissionSet, ResourceTypeRole,
		ResourceTypePipelineTemplate, ResourceTypePipelineStep, ResourceTypePipelineRun, ResourceTypeScanConfig,
		ResourceTypeWorkflow, ResourceTypeWorkflowRun, ResourceTypeCapability, ResourceTypeTool,
		ResourceTypeRuleSource, ResourceTypeRuleOverride, ResourceTypeIngest, ResourceTypeAITriage:
		return true
	}
	return false
}

// Result represents the outcome of an action.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

// String returns the string representation of the result.
func (r Result) String() string {
	return string(r)
}

// IsValid checks if the result is valid.
func (r Result) IsValid() bool {
	switch r {
	case ResultSuccess, ResultFailure, ResultDenied:
		return true
	}
	return false
}

// Severity represents the severity level of an audit event.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// IsValid checks if the severity is valid.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// SeverityForAction returns the default severity for an action.
func SeverityForAction(a Action) Severity {
	switch a {
	// Critical - security-related actions
	case ActionUserDeleted, ActionTenantDeleted, ActionTokenRevoked,
		ActionAuthFailed, ActionPermissionDenied,
		ActionAgentRevoked, ActionAgentDeleted,
		ActionSecurityValidationFailed, ActionSecurityCrossTenantAccess:
		return SeverityCritical

	// High - privilege changes and pipeline failures
	case ActionUserSuspended, ActionUserDeactivated,
		ActionMemberRemoved, ActionMemberRoleChanged,
		ActionAgentDeactivated, ActionAgentKeyRegenerated,
		ActionRoleDeleted, ActionRoleAssigned, ActionRoleUnassigned, ActionUserRolesUpdated,
		ActionPipelineTemplateDeleted, ActionPipelineRunFailed, ActionPipelineRunCancelled:
		return SeverityHigh

	// Medium - important changes
	case ActionUserCreated, ActionUserActivated,
		ActionTenantCreated, ActionTenantUpdated,
		ActionMemberAdded, ActionInvitationAccepted,
		ActionRepositoryDeleted, ActionDataExported,
		ActionAgentCreated, ActionAgentActivated,
		ActionRoleCreated, ActionRoleUpdated,
		ActionPipelineTemplateCreated, ActionPipelineTemplateUpdated, ActionPipelineRunTriggered, ActionPipelineRunCompleted,
		ActionScanConfigCreated, ActionScanConfigTriggered,
		ActionCapabilityCreated, ActionCapabilityUpdated, ActionCapabilityDeleted,
		ActionToolCreated, ActionToolUpdated, ActionToolDeleted, ActionToolCapabilitiesSet,
		ActionRuleSourceCreated, ActionRuleSourceUpdated, ActionRuleSourceDeleted,
		ActionRuleOverrideCreated, ActionRuleOverrideUpdated, ActionRuleOverrideDeleted,
		ActionIngestFailed, ActionIngestPartialSuccess:
		return SeverityMedium

	// Low - regular operations (including agent.updated, agent.connected, agent.disconnected)
	default:
		return SeverityLow
	}
}

// Changes represents before/after values for an update operation.
type Changes struct {
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
}

// NewChanges creates a new Changes instance.
func NewChanges() *Changes {
	return &Changes{
		Before: make(map[string]any),
		After:  make(map[string]any),
	}
}

// SetBefore sets a before value.
func (c *Changes) SetBefore(key string, value any) *Changes {
	c.Before[key] = value
	return c
}

// SetAfter sets an after value.
func (c *Changes) SetAfter(key string, value any) *Changes {
	c.After[key] = value
	return c
}

// Set sets both before and after values.
func (c *Changes) Set(key string, before, after any) *Changes {
	c.Before[key] = before
	c.After[key] = after
	return c
}

// IsEmpty checks if changes are empty.
func (c *Changes) IsEmpty() bool {
	return len(c.Before) == 0 && len(c.After) == 0
}

// String returns a string representation of changes.
func (c *Changes) String() string {
	if c.IsEmpty() {
		return "no changes"
	}
	return fmt.Sprintf("before: %v, after: %v", c.Before, c.After)
}
