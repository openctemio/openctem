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
	AssetRelationship *postgres.AssetRelationshipRepository // CTEM: Asset topology graph

	// Vulnerabilities & Findings
	Vulnerability    *postgres.VulnerabilityRepository
	Finding          *postgres.FindingRepository
	FindingComment   *postgres.FindingCommentRepository
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

	// SLA & Integration
	SLA                        *postgres.SLAPolicyRepository
	Integration                *postgres.IntegrationRepository
	IntegrationSCMExt          *postgres.IntegrationSCMExtensionRepository
	IntegrationNotificationExt *postgres.IntegrationNotificationExtensionRepository
	NotificationOutbox         *postgres.NotificationOutboxRepository
	NotificationEvent          *postgres.NotificationEventRepository

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

	// Licensing (modules from database)
	Module *postgres.ModuleRepository
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
		AssetRelationship: postgres.NewAssetRelationshipRepository(db), // CTEM: Asset topology graph

		// Vulnerabilities & Findings
		Vulnerability:    postgres.NewVulnerabilityRepository(db),
		Finding:          postgres.NewFindingRepository(db),
		FindingComment:   postgres.NewFindingCommentRepository(db),
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
		SLA:         postgres.NewSLAPolicyRepository(db),
		Integration: postgres.NewIntegrationRepository(db),
		// IntegrationSCMExt and IntegrationNotificationExt initialized after Integration

		NotificationOutbox: postgres.NewNotificationOutboxRepository(db),
		NotificationEvent:  postgres.NewNotificationEventRepository(db),

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

		// Licensing (modules from database)
		Module: postgres.NewModuleRepository(db),
	}
}

// InitIntegrationExtensions initializes integration extension repositories.
// Must be called after NewRepositories.
func (r *Repositories) InitIntegrationExtensions(db *postgres.DB) {
	r.IntegrationSCMExt = postgres.NewIntegrationSCMExtensionRepository(db, r.Integration)
	r.IntegrationNotificationExt = postgres.NewIntegrationNotificationExtensionRepository(db, r.Integration)
}
