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
	ActionTenantCreated                Action = "tenant.created"
	ActionTenantUpdated                Action = "tenant.updated"
	ActionTenantDeleted                Action = "tenant.deleted"
	ActionTenantSettingsUpdated        Action = "tenant.settings_updated"
	ActionTenantModulesUpdated         Action = "tenant.modules_updated"
	ActionTenantRiskScoringUpdated     Action = "tenant.risk_scoring_updated"
	ActionTenantRiskScoresRecalculated Action = "tenant.risk_scores_recalculated"
	ActionTenantAssetSourceUpdated     Action = "tenant.asset_source_updated"
	ActionTenantAssetLifecycleUpdated  Action = "tenant.asset_lifecycle_updated"
	// ActionTenantRetestUpdated records a change to the tenant's auto-retest
	// settings (RFC-039).
	ActionTenantRetestUpdated Action = "tenant.retest_updated"

	// Asset lifecycle transitions. Emitted per batch run (worker)
	// rather than per asset so the audit log stays scannable.
	// Metadata carries counts + bounded lists of affected asset IDs.
	ActionAssetLifecycleRun       Action = "asset.lifecycle_run"
	ActionAssetMarkedStale        Action = "asset.marked_stale"
	ActionAssetReactivated        Action = "asset.reactivated"
	ActionAssetLifecycleSnoozed   Action = "asset.lifecycle_snoozed"
	ActionAssetLifecycleUnsnoozed Action = "asset.lifecycle_unsnoozed"
	// ActionAssetAttributionDecided: a person set whether an asset is the
	// organization's (RFC-036 attribution review).
	ActionAssetAttributionDecided Action = "asset.attribution_decided"
	// ActionAssetCreateMerged: a repository create (the SCM import) matched an
	// existing repository asset and attached its SCM data to it. POST
	// /assets no longer merges (a duplicate is a 409); older rows from it
	// keep this action. Metadata lists the changed field names.
	ActionAssetCreateMerged Action = "asset.create_merged"

	// Human changes to assets (API/UI). Metadata carries the names of the
	// changed fields, counts and ids, never field values.
	ActionAssetCreated           Action = "asset.created"
	ActionAssetUpdated           Action = "asset.updated"
	ActionAssetDeleted           Action = "asset.deleted"
	ActionAssetStatusChanged     Action = "asset.status_changed"
	ActionAssetBulkStatusChanged Action = "asset.bulk_status_changed"
	ActionAssetCrownJewelChanged Action = "asset.crown_jewel_changed"
	ActionAssetImported          Action = "asset.imported"

	// Membership actions
	ActionMemberAdded       Action = "member.added"
	ActionMemberRemoved     Action = "member.removed"
	ActionMemberRoleChanged Action = "member.role_changed"
	ActionMemberSuspended   Action = "member.suspended"
	ActionMemberReactivated Action = "member.reactivated"

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
	// ActionFindingEvidenceAdded records a manually-attached piece of evidence
	// (note/file) on a generic (non-pentest) finding.
	ActionFindingEvidenceAdded Action = "finding.evidence_added"
	// ActionFindingEvidenceDeleted records the removal of a manually-attached
	// evidence note from a generic (non-pentest) finding.
	ActionFindingEvidenceDeleted Action = "finding.evidence_deleted"
	// ActionFindingRemediationStepAdded records a manually-appended remediation
	// step on a generic finding.
	ActionFindingRemediationStepAdded Action = "finding.remediation_step_added"
	// ActionFindingRetestRequested records a user pressing "Retest now" on a
	// finding (RFC-039): who, which finding, which template against which target.
	ActionFindingRetestRequested Action = "finding.retest_requested"
	// ActionFindingCommentReactionRemoved records an administrator removing
	// another member's reaction from a finding comment (moderation). A
	// person adding or removing their own reaction is not audited.
	ActionFindingCommentReactionRemoved Action = "finding.comment_reaction_removed"
	// ActionFindingDuplicateMarked records a user folding a finding into the
	// one it duplicates (RFC-043 §9): which finding, into which, both statuses.
	ActionFindingDuplicateMarked Action = "finding.duplicate_marked"

	// Branch actions
	ActionBranchCreated    Action = "branch.created"
	ActionBranchUpdated    Action = "branch.updated"
	ActionBranchDeleted    Action = "branch.deleted"
	ActionBranchScanned    Action = "branch.scanned"
	ActionBranchSetDefault Action = "branch.set_default"

	// SLA Policy actions
	ActionSLAPolicyCreated Action = "sla_policy.created"

	// Saved list views (D15).
	ActionSavedViewCreated Action = "saved_view.created"
	ActionSavedViewUpdated Action = "saved_view.updated"
	ActionSavedViewDeleted Action = "saved_view.deleted"
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

	// Account security actions (the user acting on their own account).
	ActionAuthMFAEnabled                  Action = "auth.mfa_enabled"
	ActionAuthMFADisabled                 Action = "auth.mfa_disabled"
	ActionAuthMFAReset                    Action = "auth.mfa_reset"
	ActionAuthMFAFailed                   Action = "auth.mfa_failed"
	ActionAuthMFARecoveryCodeUsed         Action = "auth.mfa_recovery_code_used"
	ActionAuthMFARecoveryCodesRegenerated Action = "auth.mfa_recovery_codes_regenerated"
	ActionAuthSessionRevoked              Action = "auth.session_revoked"
	ActionAuthPasswordChanged             Action = "auth.password_changed"

	// Settings actions
	ActionSettingsUpdated Action = "settings.updated"

	// Data actions
	ActionDataExported Action = "data.exported"
	ActionDataImported Action = "data.imported"

	// Sensor actions
	ActionSensorCreated        Action = "sensor.created"
	ActionSensorUpdated        Action = "sensor.updated"
	ActionSensorDeleted        Action = "sensor.deleted"
	ActionSensorActivated      Action = "sensor.activated"
	ActionSensorDeactivated    Action = "sensor.deactivated"
	ActionSensorRevoked        Action = "sensor.revoked"
	ActionSensorKeyRegenerated Action = "sensor.key_regenerated"
	ActionSensorConnected      Action = "sensor.connected"
	ActionSensorDisconnected   Action = "sensor.disconnected"
	// ActionSensorKeyRenewed records a sensor rotating its OWN credential via
	// POST /agent/renew (self-service, kubelet-style), as opposed to the admin
	// hard rotation recorded by ActionSensorKeyRegenerated.
	ActionSensorKeyRenewed Action = "sensor.key_renewed"
	// ActionSensorKeyRenewalRefused records a renewal refused because the key
	// it authenticated with was revoked, expired or regenerated (or the
	// sensor disabled) before it could rotate. A security signal: the old
	// key is still in use after an administrator killed it.
	ActionSensorKeyRenewalRefused Action = "sensor.key_renewal_refused"
	// ActionSensorIdentityCloned records the platform seeing two live sensor
	// processes use the same key (RFC-032 Phase 0 clone detection).
	ActionSensorIdentityCloned Action = "sensor.identity_cloned"
	// ActionSensorJobRefusedByLocalPolicy records a sensor refusing a job
	// because the local policy its network owner installed forbids it
	// (RFC-040 §5.7, detection A11): the platform asked for something the
	// owner does not allow.
	ActionSensorJobRefusedByLocalPolicy Action = "sensor.job_refused_local_policy"
	// ActionSensorContentRefreshRequested records an administrator asking a
	// sensor (or the fleet) to refresh its scanner content (RFC-031).
	ActionSensorContentRefreshRequested Action = "sensor.content_refresh_requested"
	// ActionSensorContentPolicyUpdated records a change of the tenant's
	// scanner content policy (RFC-031).
	ActionSensorContentPolicyUpdated Action = "sensor.content_policy_updated"
	// ActionSensorCommandsReleased records the platform taking back the
	// commands a sensor held when it was revoked or disabled (RFC-040 §5.2):
	// which were re-queued for another sensor and which were failed.
	ActionSensorCommandsReleased Action = "sensor.commands_released"

	// ActionIntegrationSyncRequested records a connector sync queued for an
	// integration's sensor (RFC-047), by a person or by the schedule.
	ActionIntegrationSyncRequested Action = "integration.sync_requested"

	// Sensor results without a command (RFC-040 §5.3).
	// ActionSensorResultsQuarantined records an unsolicited report held for
	// review instead of applied.
	ActionSensorResultsQuarantined Action = "sensor.results_quarantined"
	// ActionSensorResultsAccepted records a person accepting a quarantined
	// report (it is then applied).
	ActionSensorResultsAccepted Action = "sensor.results_accepted"
	// ActionSensorResultsDiscarded records a person discarding one.
	ActionSensorResultsDiscarded Action = "sensor.results_discarded"
	// ActionSensorResultPolicyUpdated records a change of the tenant's
	// policy for unsolicited sensor results.
	ActionSensorResultPolicyUpdated Action = "sensor.result_policy_updated"

	// Scan zone actions (RFC-023): every change to a zone or to which sensors
	// serve it.
	ActionScanZoneCreated          Action = "scan_zone.created"
	ActionScanZoneUpdated          Action = "scan_zone.updated"
	ActionScanZoneDeleted          Action = "scan_zone.deleted"
	ActionScanZoneSensorAssigned   Action = "scan_zone.sensor_assigned"
	ActionScanZoneSensorUnassigned Action = "scan_zone.sensor_unassigned"

	// API key (oct_) actions — tenant-scoped programmatic credentials.
	ActionAPIKeyCreated Action = "api_key.created"
	ActionAPIKeyRevoked Action = "api_key.revoked"
	ActionAPIKeyDeleted Action = "api_key.deleted"

	// Credential (Secret Store) actions
	ActionCredentialCreated  Action = "credential.created"
	ActionCredentialUpdated  Action = "credential.updated"
	ActionCredentialDeleted  Action = "credential.deleted"
	ActionCredentialAccessed Action = "credential.accessed"
	// ActionCredentialRevealed records that a user was shown a leaked
	// credential's plaintext secret (POST /credentials/{id}/reveal).
	ActionCredentialRevealed Action = "credential.revealed"

	// Template source credential binding: a stored credential is attached to
	// (or detached from) a template source, whose sync sends it to the
	// source's URL.
	ActionTemplateSourceCredentialAttached Action = "template_source.credential_attached"
	ActionTemplateSourceCredentialDetached Action = "template_source.credential_detached"

	// Organization SSO trust (SAML, OIDC identity providers, verified
	// domains). Usually changed by a platform administrator on the
	// organization's behalf, and always recorded in the organization's log.
	ActionSSOSAMLConfigUpdated       Action = "sso.saml_config_updated"
	ActionSSOSAMLConfigDeleted       Action = "sso.saml_config_deleted"
	ActionSSOIdentityProviderCreated Action = "sso.identity_provider_created"
	ActionSSOIdentityProviderUpdated Action = "sso.identity_provider_updated"
	ActionSSOIdentityProviderDeleted Action = "sso.identity_provider_deleted"
	ActionSSOVerifiedDomainAdded     Action = "sso.verified_domain_added"
	ActionSSOVerifiedDomainVerified  Action = "sso.verified_domain_verified"
	ActionSSOVerifiedDomainDeleted   Action = "sso.verified_domain_deleted"
	// A platform administrator's SAML / identity-provider change waits for an
	// owner of the organization, who approves (applies) or rejects it.
	ActionSSOChangeRequested Action = "sso.change_requested"
	ActionSSOChangeApproved  Action = "sso.change_approved"
	ActionSSOChangeRejected  Action = "sso.change_rejected"
	// ActionSCIMGroupMappingsUpdated: the SCIM group -> role mappings were
	// replaced. Changes carry the before/after mapping of every group that
	// changed; mapping a group to or from admin is owner-only.
	ActionSCIMGroupMappingsUpdated Action = "scim.group_mappings_updated"

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
	ActionToolActivated       Action = "tool.activated"
	ActionToolDeactivated     Action = "tool.deactivated"
	// A tenant's configuration of a tool (enabled flag and settings).
	ActionToolConfigUpdated Action = "tool.config_updated"
	ActionToolConfigDeleted Action = "tool.config_deleted"

	// Scope actions: what may be scanned (targets) and what must not be
	// (exclusions). Every change is audited with before/after (RFC-040
	// §5.11); a change that widens what is scanned is high severity.
	ActionScopeTargetCreated        Action = "scope_target.created"
	ActionScopeTargetUpdated        Action = "scope_target.updated"
	ActionScopeTargetDeleted        Action = "scope_target.deleted"
	ActionScopeTargetActivated      Action = "scope_target.activated"
	ActionScopeTargetDeactivated    Action = "scope_target.deactivated"
	ActionScopeExclusionCreated     Action = "scope_exclusion.created"
	ActionScopeExclusionUpdated     Action = "scope_exclusion.updated"
	ActionScopeExclusionDeleted     Action = "scope_exclusion.deleted"
	ActionScopeExclusionActivated   Action = "scope_exclusion.activated"
	ActionScopeExclusionDeactivated Action = "scope_exclusion.deactivated"
	ActionScopeExclusionApproved    Action = "scope_exclusion.approved"
	ActionScopeExclusionRejected    Action = "scope_exclusion.rejected"

	// Suppression rule approvals. A self-approval (the owner approving their
	// own rule because nobody else can, owner decision B16) is Critical.
	ActionSuppressionRuleApproved     Action = "suppression_rule.approved"
	ActionSuppressionRuleSelfApproved Action = "suppression_rule.self_approved"

	// Report schedule actions: a schedule mails organization posture to its
	// recipients (members or the allowed domains, D12).
	ActionReportScheduleCreated   Action = "report_schedule.created"
	ActionReportScheduleActivated Action = "report_schedule.activated"
	ActionReportScheduleDeleted   Action = "report_schedule.deleted"
	// EASM seeds (RFC-036 §6.3): what discovery expands from.
	ActionEASMSeedCreated Action = "easm_seed.created"
	ActionEASMSeedUpdated Action = "easm_seed.updated"
	ActionEASMSeedDeleted Action = "easm_seed.deleted"

	// Scanner template actions: custom templates are code a sensor runs.
	ActionScannerTemplateCreated    Action = "scanner_template.created"
	ActionScannerTemplateUpdated    Action = "scanner_template.updated"
	ActionScannerTemplateDeprecated Action = "scanner_template.deprecated"
	ActionScannerTemplateDeleted    Action = "scanner_template.deleted"

	// Asset Ownership actions
	ActionAssetAssigned         Action = "asset.assigned"
	ActionAssetUnassigned       Action = "asset.unassigned"
	ActionAssetOwnershipUpdated Action = "asset.ownership_updated"

	// Explicit per-user data-scope grants on an asset (asset_access_grants).
	ActionAssetAccessGranted Action = "asset.access_granted"
	ActionAssetAccessRevoked Action = "asset.access_revoked"

	// Permission Set actions
	// Permission sets were removed (permissions come only from roles). The
	// actions stay so historical audit rows still render.
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
	ActionPipelineRunPartial          Action = "pipeline_run.partial"
	ActionPipelineRunFailed           Action = "pipeline_run.failed"
	ActionPipelineRunCanceled         Action = "pipeline_run.canceled"

	// Pentest campaign team actions
	ActionCampaignMemberAdded       Action = "campaign.member_added"
	ActionCampaignMemberRemoved     Action = "campaign.member_removed"
	ActionCampaignMemberRoleChanged Action = "campaign.member_role_changed"
	ActionCampaignCreated           Action = "campaign.created"
	ActionCampaignUpdated           Action = "campaign.updated"
	ActionCampaignStatusChanged     Action = "campaign.status_changed"
	ActionCampaignDeleted           Action = "campaign.deleted"

	// Remediation campaign actions (Mobilization). Distinct from the pentest
	// campaign.* actions above: a different resource with its own lifecycle.
	ActionRemediationCampaignCreated       Action = "remediation_campaign.created"
	ActionRemediationCampaignUpdated       Action = "remediation_campaign.updated"
	ActionRemediationCampaignStatusChanged Action = "remediation_campaign.status_changed"
	ActionRemediationCampaignDeleted       Action = "remediation_campaign.deleted"

	// Scan config actions
	ActionScanConfigCreated   Action = "scan_config.created"
	ActionScanConfigUpdated   Action = "scan_config.updated"
	ActionScanConfigDeleted   Action = "scan_config.deleted"
	ActionScanConfigTriggered Action = "scan_config.triggered"
	ActionScanConfigPaused    Action = "scan_config.paused"
	ActionScanConfigActivated Action = "scan_config.activated"
	ActionScanConfigDisabled  Action = "scan_config.disabled"
	ActionScanConfigExported  Action = "scan_config.exported"
	ActionScanConfigImported  Action = "scan_config.imported"

	// Scan profile actions
	ActionScanProfileCreated            Action = "scan_profile.created"
	ActionScanProfileUpdated            Action = "scan_profile.updated"
	ActionScanProfileDeleted            Action = "scan_profile.deleted"
	ActionScanProfileDefaultSet         Action = "scan_profile.default_set"
	ActionScanProfileCloned             Action = "scan_profile.cloned"
	ActionScanProfileQualityGateUpdated Action = "scan_profile.quality_gate_updated"

	// Sensor command actions (made by a user through the API; the sensor's own
	// poll/ack/complete traffic is not audited here)
	ActionCommandCreated  Action = "command.created"
	ActionCommandCanceled Action = "command.canceled"
	ActionCommandDeleted  Action = "command.deleted"

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
	ActionWorkflowRunCanceled  Action = "workflow_run.canceled"

	// Rule actions
	ActionRuleSourceCreated   Action = "rule_source.created"
	ActionRuleSourceUpdated   Action = "rule_source.updated"
	ActionRuleSourceDeleted   Action = "rule_source.deleted"
	ActionRuleOverrideCreated Action = "rule_override.created"
	ActionRuleOverrideUpdated Action = "rule_override.updated"
	ActionRuleOverrideDeleted Action = "rule_override.deleted"

	// Ingest actions (sensor upload)
	ActionIngestStarted        Action = "ingest.started"
	ActionIngestCompleted      Action = "ingest.completed"
	ActionIngestFailed         Action = "ingest.failed"
	ActionIngestPartialSuccess Action = "ingest.partial_success"
	// Coverage-scoped auto-resolve of non-repository findings: what a dry
	// run (or a run held by the blinding guard) would have closed, and what
	// an enforcing run closed.
	ActionIngestCoverageAutoResolveDryRun Action = "ingest.coverage_auto_resolve_dry_run"
	ActionIngestCoverageAutoResolved      Action = "ingest.coverage_auto_resolved"
	// Source-asserted resolve (RFC-047): what a dry run would have closed
	// because the source (Tenable.sc) reported it mitigated, and what an
	// enforcing run closed.
	ActionIngestSourceResolveDryRun Action = "ingest.source_resolve_dry_run"
	ActionIngestSourceResolved      Action = "ingest.source_resolved"

	// AI Triage actions
	ActionAITriageRequested       Action = "ai_triage.requested"
	ActionAITriageStarted         Action = "ai_triage.started"
	ActionAITriageCompleted       Action = "ai_triage.completed"
	ActionAITriageFailed          Action = "ai_triage.failed"
	ActionAITriageBulk            Action = "ai_triage.bulk_requested"
	ActionAITriageRateLimit       Action = "ai_triage.rate_limited"
	ActionAITriageTokenLimit      Action = "ai_triage.token_limit_exceeded"
	ActionAITriageNeedsReview     Action = "ai_triage.needs_review"     // validator flagged output
	ActionAITriageBudgetExhausted Action = "ai_triage.budget_exhausted" // tenant hit monthly token ceiling

	// MCP actions — read-only Model Context Protocol tool invocations by an
	// `oct_` API key. Every tools/call is audited (success and error alike).
	ActionMCPToolCalled Action = "mcp.tool_called"
	// ActionMCPPromptGotten records a prompts/get: an AI client pulled a report
	// section template pre-filled with campaign/finding context. Audited because
	// it reads the same gated pentest data a tools/call does.
	ActionMCPPromptGotten Action = "mcp.prompt_gotten"

	// ActionAuditChainRebaselined records an admin re-signing the tenant's
	// tamper-evident audit hash-chain (POST /audit-logs/rebaseline). The
	// overwritten hashes are archived in audit_chain_rebaseline_entries.
	ActionAuditChainRebaselined Action = "audit.chain_rebaselined"
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
		ActionTenantCreated, ActionTenantUpdated, ActionTenantDeleted, ActionTenantSettingsUpdated, ActionTenantModulesUpdated,
		ActionTenantRiskScoringUpdated, ActionTenantRiskScoresRecalculated, ActionTenantAssetSourceUpdated,
		ActionTenantAssetLifecycleUpdated, ActionTenantRetestUpdated,
		ActionAssetLifecycleRun, ActionAssetMarkedStale, ActionAssetReactivated,
		ActionAssetLifecycleSnoozed, ActionAssetLifecycleUnsnoozed, ActionAssetAttributionDecided,
		ActionAssetCreateMerged,
		ActionAssetCreated, ActionAssetUpdated, ActionAssetDeleted, ActionAssetStatusChanged,
		ActionAssetBulkStatusChanged, ActionAssetCrownJewelChanged, ActionAssetImported,
		ActionMemberAdded, ActionMemberRemoved, ActionMemberRoleChanged,
		ActionMemberSuspended, ActionMemberReactivated,
		ActionInvitationCreated, ActionInvitationAccepted, ActionInvitationDeleted, ActionInvitationExpired,
		ActionRepositoryCreated, ActionRepositoryUpdated, ActionRepositoryDeleted, ActionRepositoryArchived,
		ActionComponentCreated, ActionComponentUpdated, ActionComponentDeleted,
		ActionVulnerabilityCreated, ActionVulnerabilityUpdated, ActionVulnerabilityDeleted,
		ActionFindingCreated, ActionFindingUpdated, ActionFindingDeleted, ActionFindingStatusChanged,
		ActionFindingTriaged, ActionFindingAssigned, ActionFindingUnassigned, ActionFindingCommented, ActionFindingBulkUpdated,
		ActionFindingEvidenceAdded, ActionFindingEvidenceDeleted, ActionFindingRemediationStepAdded,
		ActionFindingRetestRequested,
		ActionFindingCommentReactionRemoved, ActionFindingDuplicateMarked,
		ActionBranchCreated, ActionBranchUpdated, ActionBranchDeleted, ActionBranchScanned, ActionBranchSetDefault,
		ActionSLAPolicyCreated, ActionSLAPolicyUpdated, ActionSLAPolicyDeleted,
		ActionSavedViewCreated, ActionSavedViewUpdated, ActionSavedViewDeleted,
		ActionScanStarted, ActionScanCompleted, ActionScanFailed,
		ActionAuthLogin, ActionAuthLogout, ActionAuthRegister, ActionAuthFailed, ActionPermissionDenied, ActionTokenRevoked,
		ActionAuthMFAEnabled, ActionAuthMFADisabled, ActionAuthMFAReset, ActionAuthMFAFailed, ActionAuthMFARecoveryCodeUsed,
		ActionAuthMFARecoveryCodesRegenerated, ActionAuthSessionRevoked, ActionAuthPasswordChanged,
		ActionSettingsUpdated, ActionDataExported, ActionDataImported,
		ActionSensorCreated, ActionSensorUpdated, ActionSensorDeleted,
		ActionSensorActivated, ActionSensorDeactivated, ActionSensorRevoked,
		ActionSensorKeyRegenerated, ActionSensorConnected, ActionSensorDisconnected, ActionSensorKeyRenewed,
		ActionSensorKeyRenewalRefused, ActionSensorIdentityCloned, ActionSensorJobRefusedByLocalPolicy,
		ActionSensorContentRefreshRequested, ActionSensorContentPolicyUpdated, ActionSensorCommandsReleased,
		ActionSensorResultsQuarantined, ActionSensorResultsAccepted, ActionSensorResultsDiscarded,
		ActionSensorResultPolicyUpdated,
		ActionIntegrationSyncRequested,
		ActionScanZoneCreated, ActionScanZoneUpdated, ActionScanZoneDeleted,
		ActionScanZoneSensorAssigned, ActionScanZoneSensorUnassigned,
		ActionAPIKeyCreated, ActionAPIKeyRevoked, ActionAPIKeyDeleted,
		ActionCredentialCreated, ActionCredentialUpdated, ActionCredentialDeleted, ActionCredentialAccessed,
		ActionCredentialRevealed,
		ActionTemplateSourceCredentialAttached, ActionTemplateSourceCredentialDetached,
		ActionGroupCreated, ActionGroupUpdated, ActionGroupDeleted,
		ActionSSOSAMLConfigUpdated, ActionSSOSAMLConfigDeleted,
		ActionSSOIdentityProviderCreated, ActionSSOIdentityProviderUpdated, ActionSSOIdentityProviderDeleted,
		ActionSSOVerifiedDomainAdded, ActionSSOVerifiedDomainVerified, ActionSSOVerifiedDomainDeleted,
		ActionSSOChangeRequested, ActionSSOChangeApproved, ActionSSOChangeRejected,
		ActionSCIMGroupMappingsUpdated,
		ActionCapabilityCreated, ActionCapabilityUpdated, ActionCapabilityDeleted,
		ActionToolCreated, ActionToolUpdated, ActionToolDeleted, ActionToolCapabilitiesSet,
		ActionToolActivated, ActionToolDeactivated, ActionToolConfigUpdated, ActionToolConfigDeleted,
		ActionScopeTargetCreated, ActionScopeTargetUpdated, ActionScopeTargetDeleted,
		ActionScopeTargetActivated, ActionScopeTargetDeactivated,
		ActionScopeExclusionCreated, ActionScopeExclusionUpdated, ActionScopeExclusionDeleted,
		ActionScopeExclusionActivated, ActionScopeExclusionDeactivated,
		ActionScopeExclusionApproved, ActionScopeExclusionRejected,
		ActionSuppressionRuleApproved, ActionSuppressionRuleSelfApproved,
		ActionReportScheduleCreated, ActionReportScheduleActivated, ActionReportScheduleDeleted,
		ActionEASMSeedCreated, ActionEASMSeedUpdated, ActionEASMSeedDeleted,
		ActionScannerTemplateCreated, ActionScannerTemplateUpdated,
		ActionScannerTemplateDeprecated, ActionScannerTemplateDeleted,
		ActionAssetAssigned, ActionAssetUnassigned, ActionAssetOwnershipUpdated,
		ActionAssetAccessGranted, ActionAssetAccessRevoked,
		ActionPermissionSetCreated, ActionPermissionSetUpdated, ActionPermissionSetDeleted,
		ActionPermissionSetAssigned, ActionPermissionSetUnassigned,
		ActionPermissionGranted, ActionPermissionRevoked,
		ActionRoleCreated, ActionRoleUpdated, ActionRoleDeleted,
		ActionRoleAssigned, ActionRoleUnassigned, ActionUserRolesUpdated,
		ActionPipelineTemplateCreated, ActionPipelineTemplateUpdated, ActionPipelineTemplateDeleted,
		ActionPipelineTemplateActivated, ActionPipelineTemplateDeactivated,
		ActionPipelineStepCreated, ActionPipelineStepUpdated, ActionPipelineStepDeleted,
		ActionPipelineRunTriggered, ActionPipelineRunCompleted, ActionPipelineRunPartial, ActionPipelineRunFailed, ActionPipelineRunCanceled,
		ActionScanConfigCreated, ActionScanConfigUpdated, ActionScanConfigDeleted, ActionScanConfigTriggered,
		ActionScanConfigPaused, ActionScanConfigActivated, ActionScanConfigDisabled,
		ActionScanConfigExported, ActionScanConfigImported,
		ActionScanProfileCreated, ActionScanProfileUpdated, ActionScanProfileDeleted,
		ActionScanProfileDefaultSet, ActionScanProfileCloned, ActionScanProfileQualityGateUpdated,
		ActionCommandCreated, ActionCommandCanceled, ActionCommandDeleted,
		ActionSecurityValidationFailed, ActionSecurityCrossTenantAccess,
		ActionWorkflowCreated, ActionWorkflowUpdated, ActionWorkflowDeleted,
		ActionWorkflowActivated, ActionWorkflowDeactivated,
		ActionWorkflowRunTriggered, ActionWorkflowRunCompleted, ActionWorkflowRunFailed, ActionWorkflowRunCanceled,
		ActionRuleSourceCreated, ActionRuleSourceUpdated, ActionRuleSourceDeleted,
		ActionRuleOverrideCreated, ActionRuleOverrideUpdated, ActionRuleOverrideDeleted,
		ActionIngestStarted, ActionIngestCompleted, ActionIngestFailed, ActionIngestPartialSuccess,
		ActionIngestCoverageAutoResolveDryRun, ActionIngestCoverageAutoResolved,
		ActionIngestSourceResolveDryRun, ActionIngestSourceResolved,
		ActionAITriageRequested, ActionAITriageStarted, ActionAITriageCompleted, ActionAITriageFailed,
		ActionAITriageBulk, ActionAITriageRateLimit, ActionAITriageTokenLimit, ActionAITriageNeedsReview,
		ActionAITriageBudgetExhausted,
		ActionCampaignCreated, ActionCampaignUpdated, ActionCampaignStatusChanged, ActionCampaignDeleted,
		ActionCampaignMemberAdded, ActionCampaignMemberRemoved, ActionCampaignMemberRoleChanged,
		ActionRemediationCampaignCreated, ActionRemediationCampaignUpdated,
		ActionRemediationCampaignStatusChanged, ActionRemediationCampaignDeleted,
		ActionMCPToolCalled, ActionMCPPromptGotten,
		ActionAuditChainRebaselined:
		return true
	}
	return isConfigAction(a) || isRegisteredAction(a)
}

// Category returns the category of the action (e.g., "user", "tenant").
func (a Action) Category() string {
	switch a.Canonical() {
	case ActionUserCreated, ActionUserUpdated, ActionUserDeleted,
		ActionUserSuspended, ActionUserActivated, ActionUserDeactivated,
		ActionUserLogin, ActionUserLogout:
		return "user"
	case ActionTenantCreated, ActionTenantUpdated, ActionTenantDeleted, ActionTenantSettingsUpdated, ActionTenantModulesUpdated,
		ActionTenantRiskScoringUpdated, ActionTenantRiskScoresRecalculated:
		return "tenant"
	case ActionMemberAdded, ActionMemberRemoved, ActionMemberRoleChanged,
		ActionMemberSuspended, ActionMemberReactivated:
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
		ActionFindingTriaged, ActionFindingAssigned, ActionFindingUnassigned, ActionFindingCommented, ActionFindingBulkUpdated,
		ActionFindingEvidenceAdded, ActionFindingEvidenceDeleted, ActionFindingRemediationStepAdded,
		ActionFindingRetestRequested, ActionFindingCommentReactionRemoved, ActionFindingDuplicateMarked:
		return "finding"
	case ActionSavedViewCreated, ActionSavedViewUpdated, ActionSavedViewDeleted:
		return "saved_view"
	case ActionSLAPolicyCreated, ActionSLAPolicyUpdated, ActionSLAPolicyDeleted:
		return "sla_policy"
	case ActionScanStarted, ActionScanCompleted, ActionScanFailed:
		return "scan"
	case ActionAuthLogin, ActionAuthLogout, ActionAuthRegister, ActionAuthFailed, ActionPermissionDenied, ActionTokenRevoked,
		ActionAuthMFAEnabled, ActionAuthMFADisabled, ActionAuthMFAReset, ActionAuthMFAFailed, ActionAuthMFARecoveryCodeUsed,
		ActionAuthMFARecoveryCodesRegenerated, ActionAuthSessionRevoked, ActionAuthPasswordChanged:
		return "security"
	case ActionSettingsUpdated:
		return "settings"
	case ActionDataExported, ActionDataImported:
		return "data"
	case ActionSensorCreated, ActionSensorUpdated, ActionSensorDeleted,
		ActionSensorActivated, ActionSensorDeactivated, ActionSensorRevoked,
		ActionSensorKeyRegenerated, ActionSensorConnected, ActionSensorDisconnected, ActionSensorKeyRenewed,
		ActionSensorKeyRenewalRefused, ActionSensorIdentityCloned, ActionSensorJobRefusedByLocalPolicy,
		ActionSensorContentRefreshRequested, ActionSensorContentPolicyUpdated, ActionSensorCommandsReleased,
		ActionSensorResultsQuarantined, ActionSensorResultsAccepted, ActionSensorResultsDiscarded,
		ActionSensorResultPolicyUpdated:
		return "sensor"
	case ActionScanZoneCreated, ActionScanZoneUpdated, ActionScanZoneDeleted,
		ActionScanZoneSensorAssigned, ActionScanZoneSensorUnassigned:
		return "scan_zone"
	case ActionIntegrationSyncRequested:
		return "integration"
	case ActionAPIKeyCreated, ActionAPIKeyRevoked, ActionAPIKeyDeleted:
		return "api_key"
	case ActionCapabilityCreated, ActionCapabilityUpdated, ActionCapabilityDeleted:
		return "capability"
	case ActionToolCreated, ActionToolUpdated, ActionToolDeleted, ActionToolCapabilitiesSet,
		ActionToolActivated, ActionToolDeactivated, ActionToolConfigUpdated, ActionToolConfigDeleted:
		return "tool"
	case ActionScopeTargetCreated, ActionScopeTargetUpdated, ActionScopeTargetDeleted,
		ActionScopeTargetActivated, ActionScopeTargetDeactivated,
		ActionScopeExclusionCreated, ActionScopeExclusionUpdated, ActionScopeExclusionDeleted,
		ActionScopeExclusionActivated, ActionScopeExclusionDeactivated,
		ActionScopeExclusionApproved, ActionScopeExclusionRejected,
		ActionEASMSeedCreated, ActionEASMSeedUpdated, ActionEASMSeedDeleted:
		return "scope"
	case ActionSuppressionRuleApproved, ActionSuppressionRuleSelfApproved:
		return "suppression"
	case ActionReportScheduleCreated, ActionReportScheduleActivated, ActionReportScheduleDeleted:
		return "report_schedule"
	case ActionScannerTemplateCreated, ActionScannerTemplateUpdated,
		ActionScannerTemplateDeprecated, ActionScannerTemplateDeleted:
		return "scanner_template"
	case ActionRuleSourceCreated, ActionRuleSourceUpdated, ActionRuleSourceDeleted,
		ActionRuleOverrideCreated, ActionRuleOverrideUpdated, ActionRuleOverrideDeleted:
		return "rule"
	case ActionIngestStarted, ActionIngestCompleted, ActionIngestFailed, ActionIngestPartialSuccess,
		ActionIngestCoverageAutoResolveDryRun, ActionIngestCoverageAutoResolved,
		ActionIngestSourceResolveDryRun, ActionIngestSourceResolved:
		return "ingest"
	case ActionAITriageRequested, ActionAITriageStarted, ActionAITriageCompleted, ActionAITriageFailed,
		ActionAITriageBulk, ActionAITriageRateLimit, ActionAITriageTokenLimit, ActionAITriageNeedsReview,
		ActionAITriageBudgetExhausted:
		return "ai_triage"
	case ActionCampaignCreated, ActionCampaignUpdated, ActionCampaignStatusChanged, ActionCampaignDeleted,
		ActionCampaignMemberAdded, ActionCampaignMemberRemoved, ActionCampaignMemberRoleChanged:
		return "pentest_campaign"
	case ActionRemediationCampaignCreated, ActionRemediationCampaignUpdated,
		ActionRemediationCampaignStatusChanged, ActionRemediationCampaignDeleted:
		return "remediation_campaign"
	case ActionMCPToolCalled, ActionMCPPromptGotten:
		return "mcp"
	case ActionAuditChainRebaselined:
		return "audit"
	case ActionSSOSAMLConfigUpdated, ActionSSOSAMLConfigDeleted,
		ActionSSOIdentityProviderCreated, ActionSSOIdentityProviderUpdated, ActionSSOIdentityProviderDeleted,
		ActionSSOVerifiedDomainAdded, ActionSSOVerifiedDomainVerified, ActionSSOVerifiedDomainDeleted,
		ActionSSOChangeRequested, ActionSSOChangeApproved, ActionSSOChangeRejected,
		ActionSCIMGroupMappingsUpdated:
		return "sso"
	}
	if c, ok := registeredCategory(a); ok {
		return c
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
	ResourceTypeCredential       ResourceType = "credential"
	ResourceTypeVulnerability    ResourceType = "vulnerability"
	ResourceTypeFinding          ResourceType = "finding"
	ResourceTypeFindingComment   ResourceType = "finding_comment"
	ResourceTypeSLAPolicy        ResourceType = "sla_policy"
	ResourceTypeSavedView        ResourceType = "saved_view"
	ResourceTypeScan             ResourceType = "scan"
	ResourceTypeAsset            ResourceType = "asset"
	ResourceTypeSettings         ResourceType = "settings"
	ResourceTypeToken            ResourceType = "token"
	ResourceTypeSensor           ResourceType = "sensor"
	ResourceTypeScanZone         ResourceType = "scan_zone"
	ResourceTypeGroup            ResourceType = "group"
	ResourceTypePermissionSet    ResourceType = "permission_set"
	ResourceTypeRole             ResourceType = "role"
	ResourceTypePipelineTemplate ResourceType = "pipeline_template"
	ResourceTypeCampaign         ResourceType = "pentest_campaign"
	// ResourceTypeRemediationCampaign is a Mobilization remediation campaign
	// (table remediation_campaigns), not a pentest campaign.
	ResourceTypeRemediationCampaign ResourceType = "remediation_campaign"
	ResourceTypePipelineStep        ResourceType = "pipeline_step"
	ResourceTypePipelineRun         ResourceType = "pipeline_run"
	ResourceTypeScanConfig          ResourceType = "scan_config"
	ResourceTypeScanProfile         ResourceType = "scan_profile"
	ResourceTypeCommand             ResourceType = "command"
	ResourceTypeWorkflow            ResourceType = "workflow"
	ResourceTypeWorkflowRun         ResourceType = "workflow_run"
	ResourceTypeCapability          ResourceType = "capability"
	ResourceTypeTool                ResourceType = "tool"
	ResourceTypeRuleSource          ResourceType = "rule_source"
	ResourceTypeRuleOverride        ResourceType = "rule_override"
	ResourceTypeIngest              ResourceType = "ingest"
	ResourceTypeAITriage            ResourceType = "ai_triage"
	ResourceTypeMCPTool             ResourceType = "mcp_tool"
	ResourceTypeMCPPrompt           ResourceType = "mcp_prompt"
	ResourceTypeAPIKey              ResourceType = "api_key"
	ResourceTypeSAMLConfig          ResourceType = "saml_config"
	ResourceTypeIdentityProvider    ResourceType = "identity_provider"
	ResourceTypeVerifiedDomain      ResourceType = "verified_domain"
	// ResourceTypeSSOChange is an SSO change waiting for an owner's approval.
	ResourceTypeSSOChange ResourceType = "sso_change"
	// ResourceTypeSCIMGroupMapping is the organization's SCIM group -> role
	// mapping set (resource id: the tenant id).
	ResourceTypeSCIMGroupMapping ResourceType = "scim_group_mapping"
	// ResourceTypeAuditChain is a tenant's audit hash-chain; the resource id
	// of a rebaseline event is the rebaseline (archive) id.
	ResourceTypeAuditChain     ResourceType = "audit_chain"
	ResourceTypeTemplateSource ResourceType = "template_source"
	ResourceTypeScopeTarget    ResourceType = "scope_target"
	ResourceTypeScopeExclusion ResourceType = "scope_exclusion"
	// ResourceTypeSuppressionRule is a finding suppression rule.
	ResourceTypeSuppressionRule ResourceType = "suppression_rule"
	ResourceTypeScannerTemplate ResourceType = "scanner_template"
	ResourceTypeIntegration     ResourceType = "integration"
	ResourceTypeReportSchedule  ResourceType = "report_schedule"
	ResourceTypeEASMSeed        ResourceType = "easm_seed"
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
		ResourceTypeFindingComment, ResourceTypeSLAPolicy, ResourceTypeSavedView, ResourceTypeScan,
		ResourceTypeAsset, ResourceTypeSettings, ResourceTypeToken, ResourceTypeSensor, ResourceTypeScanZone,
		ResourceTypeGroup, ResourceTypePermissionSet, ResourceTypeRole,
		ResourceTypePipelineTemplate, ResourceTypePipelineStep, ResourceTypePipelineRun, ResourceTypeScanConfig,
		ResourceTypeScanProfile, ResourceTypeCommand,
		ResourceTypeWorkflow, ResourceTypeWorkflowRun, ResourceTypeCapability, ResourceTypeTool,
		ResourceTypeRuleSource, ResourceTypeRuleOverride, ResourceTypeIngest, ResourceTypeAITriage,
		ResourceTypeCampaign, ResourceTypeMCPTool, ResourceTypeMCPPrompt, ResourceTypeAPIKey,
		ResourceTypeSAMLConfig, ResourceTypeIdentityProvider, ResourceTypeVerifiedDomain, ResourceTypeSSOChange,
		ResourceTypeSCIMGroupMapping,
		ResourceTypeCredential, ResourceTypeAuditChain, ResourceTypeTemplateSource,
		ResourceTypeScopeTarget, ResourceTypeScopeExclusion, ResourceTypeSuppressionRule, ResourceTypeScannerTemplate, ResourceTypeIntegration,
		ResourceTypeRemediationCampaign, ResourceTypeReportSchedule, ResourceTypeEASMSeed:
		return true
	}
	return isConfigResourceType(r)
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
		ActionSensorRevoked, ActionSensorDeleted,
		ActionSecurityValidationFailed, ActionSecurityCrossTenantAccess,
		ActionAuditChainRebaselined, ActionSuppressionRuleSelfApproved:
		return SeverityCritical

	// High - privilege changes and pipeline failures
	case ActionSSOSAMLConfigUpdated, ActionSSOSAMLConfigDeleted,
		ActionSSOIdentityProviderCreated, ActionSSOIdentityProviderUpdated, ActionSSOIdentityProviderDeleted,
		ActionSSOVerifiedDomainAdded, ActionSSOVerifiedDomainVerified, ActionSSOVerifiedDomainDeleted,
		ActionSSOChangeRequested, ActionSSOChangeApproved, ActionSSOChangeRejected,
		ActionSCIMGroupMappingsUpdated,
		ActionUserSuspended, ActionUserDeactivated,
		ActionAuthMFADisabled, ActionAuthMFAReset, ActionAuthMFAFailed, ActionAuthMFARecoveryCodeUsed,
		ActionMemberRemoved, ActionMemberRoleChanged,
		ActionCampaignMemberRemoved, ActionCampaignMemberRoleChanged, ActionCampaignDeleted,
		ActionSensorDeactivated, ActionSensorKeyRegenerated, ActionSensorKeyRenewalRefused,
		ActionAPIKeyRevoked, ActionAPIKeyDeleted,
		ActionRoleDeleted, ActionRoleAssigned, ActionRoleUnassigned, ActionUserRolesUpdated,
		ActionCredentialDeleted, ActionCredentialRevealed,
		ActionTemplateSourceCredentialAttached,
		ActionPipelineTemplateDeleted, ActionPipelineRunFailed, ActionPipelineRunCanceled,
		// Widening what sensors scan, and the code they run.
		ActionScopeTargetCreated, ActionScopeTargetActivated, ActionEASMSeedCreated,
		ActionScopeExclusionDeleted, ActionScopeExclusionDeactivated,
		ActionScannerTemplateCreated, ActionScannerTemplateUpdated,
		// Deleting an asset also deletes its findings.
		ActionAssetDeleted:
		return SeverityHigh

	// Medium - important changes
	case ActionUserCreated, ActionUserActivated,
		ActionAuthMFAEnabled, ActionAuthMFARecoveryCodesRegenerated, ActionAuthSessionRevoked, ActionAuthPasswordChanged,
		ActionTenantCreated, ActionTenantUpdated, ActionTenantModulesUpdated,
		ActionTenantRiskScoringUpdated, ActionTenantRiskScoresRecalculated, ActionTenantAssetSourceUpdated,
		ActionTenantAssetLifecycleUpdated, ActionTenantRetestUpdated,
		ActionAssetLifecycleRun, ActionAssetMarkedStale, ActionAssetReactivated,
		ActionAssetLifecycleSnoozed, ActionAssetLifecycleUnsnoozed, ActionAssetAttributionDecided,
		ActionAssetCreateMerged,
		ActionAssetBulkStatusChanged, ActionAssetCrownJewelChanged, ActionAssetImported,
		ActionMemberAdded, ActionInvitationAccepted,
		ActionCampaignCreated, ActionCampaignUpdated, ActionCampaignStatusChanged,
		ActionCampaignMemberAdded,
		ActionRepositoryDeleted, ActionDataExported,
		ActionSensorCreated, ActionSensorActivated, ActionSensorKeyRenewed,
		ActionAPIKeyCreated,
		ActionRoleCreated, ActionRoleUpdated,
		ActionPipelineTemplateCreated, ActionPipelineTemplateUpdated, ActionPipelineRunTriggered, ActionPipelineRunCompleted, ActionPipelineRunPartial,
		ActionScanConfigCreated, ActionScanConfigTriggered,
		ActionScanProfileDeleted, ActionScanProfileDefaultSet, ActionScanProfileQualityGateUpdated,
		ActionCredentialCreated, ActionCredentialUpdated, ActionCredentialAccessed,
		ActionCapabilityCreated, ActionCapabilityUpdated, ActionCapabilityDeleted,
		ActionToolCreated, ActionToolUpdated, ActionToolDeleted, ActionToolCapabilitiesSet,
		ActionToolActivated, ActionToolDeactivated, ActionToolConfigUpdated, ActionToolConfigDeleted,
		ActionScopeTargetUpdated, ActionScopeTargetDeleted, ActionScopeTargetDeactivated,
		ActionScopeExclusionCreated, ActionScopeExclusionUpdated, ActionScopeExclusionActivated,
		ActionScopeExclusionApproved, ActionScopeExclusionRejected,
		ActionSuppressionRuleApproved,
		ActionReportScheduleCreated, ActionReportScheduleActivated, ActionReportScheduleDeleted,
		ActionEASMSeedUpdated, ActionEASMSeedDeleted,
		ActionScannerTemplateDeprecated, ActionScannerTemplateDeleted,
		ActionRuleSourceCreated, ActionRuleSourceUpdated, ActionRuleSourceDeleted,
		ActionRuleOverrideCreated, ActionRuleOverrideUpdated, ActionRuleOverrideDeleted,
		ActionIngestFailed, ActionIngestPartialSuccess:
		return SeverityMedium

	// Low - regular operations (including sensor.updated, sensor.connected, sensor.disconnected)
	default:
		if sev, ok := registeredSeverity(a); ok {
			return sev
		}
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
