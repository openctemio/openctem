package main

import (
	"github.com/openctemio/api/internal/infra/postgres"
)

// Repositories holds all repository instances.
type Repositories struct {
	// Core
	User   *postgres.UserRepository
	Tenant *postgres.TenantRepository
	Audit  *postgres.AuditRepository

	// Assets & Components
	Asset             *postgres.AssetRepository
	RepoExt           *postgres.RepositoryExtensionRepository
	Component         *postgres.ComponentRepository
	AssetGroup        *postgres.AssetGroupRepository
	AssetType         *postgres.AssetTypeRepository
	AssetTypeCat      *postgres.AssetTypeCategoryRepository
	ScopeTarget       *postgres.ScopeTargetRepository
	ScopeExcl         *postgres.ScopeExclusionRepository
	ScopeSchedule     *postgres.ScopeScheduleRepository
	AssetService      *postgres.AssetServiceRepository      // CTEM: Network services on assets
	AssetStateHistory *postgres.AssetStateHistoryRepository // CTEM: State change audit log
	AssetRelationship          *postgres.AssetRelationshipRepository          // CTEM: Asset topology graph
	RelationshipSuggestion     *postgres.RelationshipSuggestionRepository     // CTEM: Relationship suggestions

	// Vulnerabilities & Findings
	Vulnerability    *postgres.VulnerabilityRepository
	Finding          *postgres.FindingRepository
	FindingComment   *postgres.FindingCommentRepository
	FindingApproval  *postgres.FindingApprovalRepository
	FindingActivity  *postgres.FindingActivityRepository
	AITriage         *postgres.AITriageRepository              // AI-powered vulnerability triage
	DataFlow         *postgres.DataFlowRepository              // Data flow traces for taint tracking
	FindingSource    *postgres.FindingSourceRepository         // Finding source configuration
	FindingSourceCat *postgres.FindingSourceCategoryRepository // Finding source categories

	// Exposures & Threat Intel
	Exposure             *postgres.ExposureRepository
	ExposureStateHistory *postgres.ExposureStateHistoryRepository
	ThreatIntel          *postgres.ThreatIntelRepository

	// Dashboard & Branch
	Dashboard *postgres.DashboardRepository
	Branch    *postgres.BranchRepository

	// Pentest
	PentestCampaign       *postgres.PentestCampaignRepository
	PentestCampaignMember *postgres.PentestCampaignMemberRepository
	PentestFinding        *postgres.PentestFindingRepository
	PentestRetest    *postgres.PentestRetestRepository
	PentestTemplate  *postgres.PentestTemplateRepository
	PentestReport    *postgres.PentestReportRepository

	// Attachments (file upload metadata)
	Attachment *postgres.AttachmentRepository

	// Compliance
	ComplianceFramework  *postgres.ComplianceFrameworkRepository
	ComplianceControl    *postgres.ComplianceControlRepository
	ComplianceAssessment *postgres.ComplianceAssessmentRepository
	ComplianceMapping    *postgres.ComplianceMappingRepository

	// Attack Simulation & Control Testing
	Simulation  *postgres.SimulationRepository
	ControlTest *postgres.ControlTestRepository

	// Threat Actor Intelligence
	ThreatActor *postgres.ThreatActorRepository

	// Remediation Campaigns
	RemediationCampaign *postgres.RemediationCampaignRepository

	// Business Units
	BusinessUnit *postgres.BusinessUnitRepository

	// SLA & Integration
	SLA                        *postgres.SLAPolicyRepository
	Integration                *postgres.IntegrationRepository
	IntegrationSCMExt          *postgres.IntegrationSCMExtensionRepository
	IntegrationNotificationExt *postgres.IntegrationNotificationExtensionRepository
	Outbox         *postgres.OutboxRepository
	OutboxEvent    *postgres.OutboxEventRepository
	Notification   *postgres.NotificationRepository

	// Agents & Commands
	Agent   *postgres.AgentRepository
	Command *postgres.CommandRepository

	// Scanning
	ScanProfile      *postgres.ScanProfileRepository
	ScanSession      *postgres.ScanSessionRepository
	Tool             *postgres.ToolRepository
	ToolCategory     *postgres.ToolCategoryRepository
	Capability       *postgres.CapabilityRepository
	ToolCapability   *postgres.ToolCapabilityRepository
	TenantToolConfig *postgres.TenantToolConfigRepository
	ToolExecution    *postgres.ToolExecutionRepository
	Scan             *postgres.ScanRepository
	ScannerTemplate  *postgres.ScannerTemplateRepository
	TemplateSource   *postgres.TemplateSourceRepository
	SecretStore      *postgres.SecretStoreRepository

	// Pipelines
	PipelineTemplate *postgres.PipelineTemplateRepository
	PipelineRun      *postgres.PipelineRunRepository
	PipelineStep     *postgres.PipelineStepRepository
	StepRun          *postgres.StepRunRepository

	// Workflows
	Workflow        *postgres.WorkflowRepository
	WorkflowNode    *postgres.WorkflowNodeRepository
	WorkflowEdge    *postgres.WorkflowEdgeRepository
	WorkflowRun     *postgres.WorkflowRunRepository
	WorkflowNodeRun *postgres.WorkflowNodeRunRepository

	// Suppressions
	Suppression *postgres.SuppressionRepository

	// Access Control
	Group          *postgres.GroupRepository
	PermissionSet  *postgres.PermissionSetRepository
	AccessControl  *postgres.AccessControlRepository
	Role           *postgres.RoleRepository
	RolePermission *postgres.PermissionRepository

	// Session (raw *sql.DB required)
	Session      *postgres.SessionRepository
	RefreshToken *postgres.RefreshTokenRepository

	// Admin (Platform Admin)
	Admin         *postgres.AdminRepository
	AdminAuditLog *postgres.AuditLogRepository

	// Target Mappings (scanner target type -> asset type)
	TargetMapping *postgres.TargetMappingRepository

	// API Keys & Webhooks
	APIKey  *postgres.APIKeyRepository
	Webhook *postgres.WebhookRepository

	// Licensing (modules from database)
	Module       *postgres.ModuleRepository
	TenantModule *postgres.TenantModuleRepository

	// SSO Identity Providers
	IdentityProvider *postgres.IdentityProviderRepository

	// KEV Escalation
	KEVEscalator *postgres.KEVEscalator

	// Report Schedules
	ReportSchedule *postgres.ReportScheduleRepository

	// Asset Dedup (RFC-001)
	AssetDedup *postgres.AssetDedupRepository

	// Priority Classification (RFC-004)
	PriorityRule  *postgres.PriorityRuleRepository
	PriorityAudit *postgres.PriorityAuditRepository
	EPSSAdapter   *postgres.EPSSAdapter
	KEVAdapter    *postgres.KEVAdapter
}

// NewRepositories initializes all repositories.
func NewRepositories(db *postgres.DB) *Repositories {
	return &Repositories{
		// Core
		User:   postgres.NewUserRepository(db),
		Tenant: postgres.NewTenantRepository(db),
		Audit:  postgres.NewAuditRepository(db),

		// Assets & Components
		Asset:             postgres.NewAssetRepository(db),
		RepoExt:           postgres.NewRepositoryExtensionRepository(db),
		Component:         postgres.NewComponentRepository(db),
		AssetGroup:        postgres.NewAssetGroupRepository(db),
		AssetType:         postgres.NewAssetTypeRepository(db),
		AssetTypeCat:      postgres.NewAssetTypeCategoryRepository(db),
		ScopeTarget:       postgres.NewScopeTargetRepository(db),
		ScopeExcl:         postgres.NewScopeExclusionRepository(db),
		ScopeSchedule:     postgres.NewScopeScheduleRepository(db),
		AssetService:      postgres.NewAssetServiceRepository(db),      // CTEM: Network services
		AssetStateHistory: postgres.NewAssetStateHistoryRepository(db), // CTEM: State change audit
		AssetRelationship:          postgres.NewAssetRelationshipRepository(db),          // CTEM: Asset topology graph
		RelationshipSuggestion:     postgres.NewRelationshipSuggestionRepository(db),     // CTEM: Relationship suggestions

		// Vulnerabilities & Findings
		Vulnerability:    postgres.NewVulnerabilityRepository(db),
		Finding:          postgres.NewFindingRepository(db),
		FindingComment:   postgres.NewFindingCommentRepository(db),
		FindingApproval:  postgres.NewFindingApprovalRepository(db),
		FindingActivity:  postgres.NewFindingActivityRepository(db),
		AITriage:         postgres.NewAITriageRepository(db),              // AI-powered vulnerability triage
		DataFlow:         postgres.NewDataFlowRepository(db),              // Data flow traces
		FindingSource:    postgres.NewFindingSourceRepository(db),         // Finding source configuration
		FindingSourceCat: postgres.NewFindingSourceCategoryRepository(db), // Finding source categories

		// Exposures & Threat Intel
		Exposure:             postgres.NewExposureRepository(db),
		ExposureStateHistory: postgres.NewExposureStateHistoryRepository(db),
		ThreatIntel:          postgres.NewThreatIntelRepository(db),

		// Dashboard & Branch
		Dashboard: postgres.NewDashboardRepository(db.DB),
		Branch:    postgres.NewBranchRepository(db),

		// SLA & Integration
		// Pentest
		PentestCampaign:       postgres.NewPentestCampaignRepository(db),
		PentestCampaignMember: postgres.NewPentestCampaignMemberRepository(db),
		PentestFinding:        postgres.NewPentestFindingRepository(db),
		PentestRetest:   postgres.NewPentestRetestRepository(db),
		PentestTemplate: postgres.NewPentestTemplateRepository(db),
		PentestReport:   postgres.NewPentestReportRepository(db),

		// Attachments
		Attachment: postgres.NewAttachmentRepository(db),

		// Compliance
		ComplianceFramework:  postgres.NewComplianceFrameworkRepository(db),
		ComplianceControl:    postgres.NewComplianceControlRepository(db),
		ComplianceAssessment: postgres.NewComplianceAssessmentRepository(db),
		ComplianceMapping:    postgres.NewComplianceMappingRepository(db),

		// Attack Simulation & Control Testing
		Simulation:  postgres.NewSimulationRepository(db),
		ControlTest: postgres.NewControlTestRepository(db),

		// Threat Actor Intelligence
		ThreatActor: postgres.NewThreatActorRepository(db),

		// Remediation Campaigns
		RemediationCampaign: postgres.NewRemediationCampaignRepository(db),

		// Business Units
		BusinessUnit: postgres.NewBusinessUnitRepository(db),

		SLA:         postgres.NewSLAPolicyRepository(db),
		Integration: postgres.NewIntegrationRepository(db),
		// IntegrationSCMExt and IntegrationNotificationExt initialized after Integration

		Outbox:       postgres.NewOutboxRepository(db),
		OutboxEvent:  postgres.NewOutboxEventRepository(db),
		Notification: postgres.NewNotificationRepository(db),

		// Agents & Commands
		Agent:   postgres.NewAgentRepository(db),
		Command: postgres.NewCommandRepository(db),

		// Scanning
		ScanProfile:      postgres.NewScanProfileRepository(db),
		ScanSession:      postgres.NewScanSessionRepository(db),
		Tool:             postgres.NewToolRepository(db),
		ToolCategory:     postgres.NewToolCategoryRepository(db),
		Capability:       postgres.NewCapabilityRepository(db),
		ToolCapability:   postgres.NewToolCapabilityRepository(db),
		TenantToolConfig: postgres.NewTenantToolConfigRepository(db),
		ToolExecution:    postgres.NewToolExecutionRepository(db),
		Scan:             postgres.NewScanRepository(db),
		ScannerTemplate:  postgres.NewScannerTemplateRepository(db),
		TemplateSource:   postgres.NewTemplateSourceRepository(db),
		SecretStore:      postgres.NewSecretStoreRepository(db),

		// Pipelines
		PipelineTemplate: postgres.NewPipelineTemplateRepository(db),
		PipelineRun:      postgres.NewPipelineRunRepository(db),
		PipelineStep:     postgres.NewPipelineStepRepository(db),
		StepRun:          postgres.NewStepRunRepository(db),

		// Workflows
		Workflow:        postgres.NewWorkflowRepository(db),
		WorkflowNode:    postgres.NewWorkflowNodeRepository(db),
		WorkflowEdge:    postgres.NewWorkflowEdgeRepository(db),
		WorkflowRun:     postgres.NewWorkflowRunRepository(db),
		WorkflowNodeRun: postgres.NewWorkflowNodeRunRepository(db),

		// Suppressions
		Suppression: postgres.NewSuppressionRepository(db),

		// Access Control
		Group:          postgres.NewGroupRepository(db),
		PermissionSet:  postgres.NewPermissionSetRepository(db),
		AccessControl:  postgres.NewAccessControlRepository(db),
		Role:           postgres.NewRoleRepository(db),
		RolePermission: postgres.NewPermissionRepository(db),

		// Session (raw *sql.DB required)
		Session:      postgres.NewSessionRepository(db.DB),
		RefreshToken: postgres.NewRefreshTokenRepository(db.DB),

		// Admin (Platform Admin)
		Admin:         postgres.NewAdminRepository(db),
		AdminAuditLog: postgres.NewAuditLogRepository(db),

		// Target Mappings
		TargetMapping: postgres.NewTargetMappingRepository(db),

		// API Keys & Webhooks
		APIKey:  postgres.NewAPIKeyRepository(db),
		Webhook: postgres.NewWebhookRepository(db),

		// Licensing (modules from database)
		Module:       postgres.NewModuleRepository(db),
		TenantModule: postgres.NewTenantModuleRepository(db),

		// SSO Identity Providers
		IdentityProvider: postgres.NewIdentityProviderRepository(db),

		// KEV Escalation
		KEVEscalator: postgres.NewKEVEscalator(db),

		// Report Schedules
		ReportSchedule: postgres.NewReportScheduleRepository(db),

		// Asset Dedup (RFC-001)
		AssetDedup: postgres.NewAssetDedupRepository(db),

		// Priority Classification (RFC-004)
		PriorityRule:  postgres.NewPriorityRuleRepository(db),
		PriorityAudit: postgres.NewPriorityAuditRepository(db),
	}
}

// InitIntegrationExtensions initializes integration extension repositories.
// Must be called after NewRepositories.
func (r *Repositories) InitIntegrationExtensions(db *postgres.DB) {
	r.IntegrationSCMExt = postgres.NewIntegrationSCMExtensionRepository(db, r.Integration)
	r.IntegrationNotificationExt = postgres.NewIntegrationNotificationExtensionRepository(db, r.Integration)
}
