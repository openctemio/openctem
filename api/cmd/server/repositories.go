package main

import (
	"github.com/openctemio/openctem/api/internal/infra/postgres"
)

// Repositories holds all repository instances.
type Repositories struct {
	// Core
	User   *postgres.UserRepository
	Tenant *postgres.TenantRepository
	Audit  *postgres.AuditRepository

	// Assets & Components
	Asset                   *postgres.AssetRepository
	RepoExt                 *postgres.RepositoryExtensionRepository
	RepoIdentity            *postgres.RepositoryIdentityRepository
	Component               *postgres.ComponentRepository
	VEXStatement            *postgres.VEXStatementRepository
	LicensePolicy           *postgres.LicensePolicyRepository
	AssetGroup              *postgres.AssetGroupRepository
	AssetType               *postgres.AssetTypeRepository
	AssetTypeCat            *postgres.AssetTypeCategoryRepository
	ScopeTarget             *postgres.ScopeTargetRepository
	ScopeExcl               *postgres.ScopeExclusionRepository
	AssetService            *postgres.AssetServiceRepository           // CTEM: Network services on assets
	WebEndpoint             *postgres.WebEndpointRepository            // Web surface: endpoints under origin assets (RFC-056)
	Software                *postgres.SoftwareRepository               // Software catalog and asset links (RFC-066)
	CVECorpus               *postgres.CVECorpusRepository              // CVE corpus for inventory matching (RFC-066)
	SoftwareMatch           *postgres.SoftwareMatchRepository          // Inventory vulnerability matcher (RFC-066)
	AssetAttributeSources   *postgres.AssetAttributeSourceRepository   // Per-source asset attribute values (RFC-069)
	AssetFreshness          *postgres.AssetFreshnessRepository         // Last observation per attribute class (RFC-075)
	AssetCoverage           *postgres.AssetCoverageRepository          // Coverage ledger (RFC-093)
	AssetWildcardDNS        *postgres.AssetWildcardDNSRepository       // Names that resolve only through a wildcard (RFC-088 A4)
	AssetEnrichmentRequests *postgres.AssetEnrichmentRequestRepository // Automatic enrichment requests (RFC-075)
	AssetChangeEvents       *postgres.AssetChangeEventRepository       // Asset change timeline (RFC-069)
	APISpec                 *postgres.APISpecRepository                // API descriptions of web origins (RFC-056)
	AssetStateHistory       *postgres.AssetStateHistoryRepository      // CTEM: State change audit log
	AssetRelationship       *postgres.AssetRelationshipRepository      // CTEM: Asset topology graph
	RelationshipSuggestion  *postgres.RelationshipSuggestionRepository // CTEM: Relationship suggestions
	ThreatModel             *postgres.ThreatModelRepository            // CTEM: Continuous threat models
	AttackerProfileReader   *postgres.AttackerProfileReader            // CTEM: Attacker profiles (generation input)

	// Vulnerabilities & Findings
	Vulnerability    *postgres.VulnerabilityRepository
	Finding          *postgres.FindingRepository
	FindingComment   *postgres.FindingCommentRepository
	CommentReaction  *postgres.CommentReactionRepository
	FindingApproval  *postgres.FindingApprovalRepository
	FindingActivity  *postgres.FindingActivityRepository
	AITriage         *postgres.AITriageRepository              // AI-powered vulnerability triage
	AITriageBudget   *postgres.AITriageBudgetRepository        // Per-tenant LLM token budget (RFC-008)
	DataFlow         *postgres.DataFlowRepository              // Data flow traces for taint tracking
	FindingSource    *postgres.FindingSourceRepository         // Finding source configuration
	FindingSourceCat *postgres.FindingSourceCategoryRepository // Finding source categories

	// Exposures & Threat Intel
	Exposure             *postgres.ExposureRepository
	ExposureStateHistory *postgres.ExposureStateHistoryRepository
	ThreatIntel          *postgres.ThreatIntelRepository
	CTEMID               *postgres.CTEMIDRepository

	// Dashboard & Branch
	Dashboard *postgres.DashboardRepository
	Branch    *postgres.BranchRepository

	// Pentest
	PentestCampaign       *postgres.PentestCampaignRepository
	PentestCampaignMember *postgres.PentestCampaignMemberRepository
	PentestSignoff        *postgres.PentestCampaignSignoffRepository
	PentestSecret         *postgres.PentestCampaignSecretRepository
	PentestRetest         *postgres.PentestRetestRepository
	PentestTemplate       *postgres.PentestTemplateRepository
	PentestReport         *postgres.PentestReportRepository
	PentestReportTemplate *postgres.PentestReportTemplateRepository
	PentestChecklistTpl   *postgres.PentestChecklistTemplateRepository
	PentestChecklist      *postgres.PentestCampaignChecklistRepository

	// Attachments (file upload metadata)
	Attachment *postgres.AttachmentRepository

	// Compliance
	ComplianceFramework  *postgres.ComplianceFrameworkRepository
	ComplianceControl    *postgres.ComplianceControlRepository
	ComplianceAssessment *postgres.ComplianceAssessmentRepository
	ComplianceMapping    *postgres.ComplianceMappingRepository

	// Attack Simulation & Control Testing
	Simulation    *postgres.SimulationRepository
	SimulationRun *postgres.SimulationRunRepository
	ControlTest   *postgres.ControlTestRepository

	// Threat Actor Intelligence
	ThreatActor *postgres.ThreatActorRepository

	// Remediation Campaigns
	RemediationCampaign       *postgres.RemediationCampaignRepository
	RemediationCampaignTicket *postgres.RemediationCampaignTicketRepository
	TicketMapping             *postgres.TicketMappingRepository
	TicketLink                *postgres.TicketLinkRepository
	FindingRemediationKey     *postgres.FindingRemediationKeyRepository

	// Business Units
	BusinessUnit *postgres.BusinessUnitRepository

	// SLA & Integration
	SLA                        *postgres.SLAPolicyRepository
	Integration                *postgres.IntegrationRepository
	IntegrationSCMExt          *postgres.IntegrationSCMExtensionRepository
	IntegrationNotificationExt *postgres.IntegrationNotificationExtensionRepository
	Outbox                     *postgres.OutboxRepository
	OutboxEvent                *postgres.OutboxEventRepository
	Notification               *postgres.NotificationRepository

	// Sensors & Commands
	Sensor       *postgres.SensorRepository
	SensorAPIKey *postgres.SensorAPIKeyRepository
	// SensorSigningKey: public keys of key-bound sensors (RFC-052).
	SensorSigningKey *postgres.SensorSigningKeyRepository
	// SensorPairing: pairing requests (RFC-052).
	SensorPairing *postgres.SensorPairingRepository
	// SensorGrant: per-sensor grants (RFC-052 §5).
	SensorGrant *postgres.SensorGrantRepository
	// CollectorAsset: which assets each trusted collector source reported (RFC-040 §12).
	CollectorAsset *postgres.CollectorAssetRepository
	// SensorReach: what a sensor's lookups may answer about (fingerprints,
	// baseline diff, suppressions).
	SensorReach *postgres.SensorReachRepository
	// SensorEvent is the sensor activity timeline (sensor_events).
	SensorEvent *postgres.SensorEventRepository
	// CommandEvent is the command lifecycle (command_events): run timelines.
	CommandEvent *postgres.CommandEventRepository
	// SensorHeartbeatHistory is the per-sensor heartbeat history behind the
	// Control channel sparkline (sensor_heartbeat_history, RFC-035).
	SensorHeartbeatHistory *postgres.SensorHeartbeatHistoryRepository
	// CommandLog keeps the per-task logs sensors send (command_logs).
	CommandLog *postgres.CommandLogRepository
	Command    *postgres.CommandRepository
	// ToolDurationStats are the learned per-target durations (research/122).
	ToolDurationStats *postgres.ToolDurationStatsRepository
	// SensorContentPolicy is the tenant scanner content policy (RFC-031).
	SensorContentPolicy *postgres.SensorContentPolicyRepository
	// SensorResult is the policy and quarantine for sensor results without a
	// command (RFC-040 §5.3).
	SensorResult *postgres.SensorResultRepository
	IngestJob    *postgres.IngestJobRepository
	// IngestReport tracks sensor protocol v2 results reports (RFC-026).
	IngestReport *postgres.IngestReportRepository

	// Scan coverage rotation (RFC-007)
	ScanCoverage *postgres.ScanCoverageRepository

	// Scan zones (RFC-023)
	ScanZone *postgres.ScanZoneRepository
	// Scan window policies, overrides and the assets behind targets (RFC-067)
	ScanWindowPolicy   *postgres.ScanWindowPolicyRepository
	ScanWindowOverride *postgres.ScanWindowOverrideRepository
	ScanWindowAsset    *postgres.ScanWindowAssetRepository
	// Content packs (RFC-061)
	ContentPack *postgres.ContentPackRepository
	// Platform content packs and channels (RFC-061)
	PlatformContentPack *postgres.PlatformContentPackRepository

	// Scanning
	ScanProfile      *postgres.ScanProfileRepository
	Tool             *postgres.ToolRepository
	ToolCategory     *postgres.ToolCategoryRepository
	Capability       *postgres.CapabilityRepository
	ToolCapability   *postgres.ToolCapabilityRepository
	TenantToolConfig *postgres.TenantToolConfigRepository
	Scan             *postgres.ScanRepository
	ScanSelector     *postgres.ScanSelectorRepository
	ScannerTemplate  *postgres.ScannerTemplateRepository
	TemplateSource   *postgres.TemplateSourceRepository
	SecretStore      *postgres.SecretStoreRepository

	// ScanRuns
	ScanWorkflow     *postgres.ScanWorkflowRepository
	ScanRun          *postgres.ScanRunRepository
	ScanWorkflowStep *postgres.ScanWorkflowStepRepository
	StepRun          *postgres.StepRunRepository

	// Workflows
	Workflow        *postgres.AutomationRepository
	WorkflowNode    *postgres.AutomationNodeRepository
	WorkflowEdge    *postgres.AutomationEdgeRepository
	WorkflowRun     *postgres.AutomationRunRepository
	WorkflowNodeRun *postgres.AutomationRunStepRepository

	// Suppressions
	Suppression *postgres.SuppressionRepository
	// FindingCorrelation stores cross-rule finding correlations.
	FindingCorrelation *postgres.FindingCorrelationRepository

	// Access Control
	Group *postgres.GroupRepository
	// GroupRoleBinding: team role bindings (decisions G1-G12).
	GroupRoleBinding *postgres.GroupRoleBindingRepository
	// ServiceAccount: organization-owned identities for integrations.
	ServiceAccount  *postgres.ServiceAccountRepository
	AccessControl   *postgres.AccessControlRepository
	DataScope       *postgres.DataScopeRepository
	MemberLifecycle *postgres.MemberLifecycleRepository
	// OwnershipTransfer: owner-to-member ownership transfer requests.
	OwnershipTransfer *postgres.OwnershipTransferRepository
	Role              *postgres.RoleRepository
	RolePermission    *postgres.PermissionRepository

	// Session (raw *sql.DB required)
	Session      *postgres.SessionRepository
	RefreshToken *postgres.RefreshTokenRepository
	// UserMFA holds user two-factor state (TOTP secret, recovery codes,
	// login challenges).
	UserMFA *postgres.UserMFARepository

	// Admin (Platform Admin)
	Admin        *postgres.AdminRepository
	SignupPolicy *postgres.SignupPolicyRepository
	// PlatformSetting stores the other console settings (RFC-079).
	PlatformSetting *postgres.PlatformSettingRepository
	ScanPolicy      *postgres.ScanPolicyRepository
	ScanApproval    *postgres.ScanApprovalRepository
	AccessRequest   *postgres.AccessRequestRepository
	Plan            *postgres.PlanRepository
	IdleLifecycle   *postgres.IdleLifecycleRepository
	AdminAuditLog   *postgres.AuditLogRepository
	AdminOrg        *postgres.AdminOrganizationRepository
	AdminConsole    *postgres.AdminConsoleRepository
	PlatformIdP     *postgres.PlatformIdPRepository

	// Target Mappings (scanner target type -> asset type)
	TargetMapping *postgres.TargetMappingRepository

	// API Keys & Webhooks
	APIKey *postgres.APIKeyRepository
	// MCPOAuth is the OAuth state of the MCP endpoint (RFC-062).
	MCPOAuth *postgres.MCPOAuthRepository

	// Licensing (modules from database)
	Module       *postgres.ModuleRepository
	TenantModule *postgres.TenantModuleRepository

	// SSO Identity Providers
	IdentityProvider *postgres.IdentityProviderRepository
	// Federated identities (issuer + subject) bound to accounts
	UserIdentity *postgres.UserIdentityRepository
	// Trusts between organizations (RFC-058)
	OrgTrust *postgres.OrgTrustRepository

	// Domain-ownership verification (SSO P1, migration 000191)
	VerifiedDomain *postgres.VerifiedDomainRepository
	CTMonitorState *postgres.CTMonitorStateRepository
	Attribution    *postgres.AttributionRepository
	EASMDNS        *postgres.EASMDNSRepository
	VerifiedNames  *postgres.VerifiedDomainNameRepository
	// CI runs, trust configurations and the gate (RFC-051)
	CIRun       *postgres.CIRunRepository
	CodeScan    *postgres.CodeScanRepository
	SCMApp      *postgres.SCMAppInstallationRepository
	EASMSummary *postgres.EASMSummaryRepository
	// EASMLookalike stores lookalike watches and candidates (RFC-083).
	EASMLookalike *postgres.EASMLookalikeRepository
	// EASMNetworkSeed stores AS number and organization seeds (RFC-082).
	EASMNetworkSeed *postgres.EASMNetworkSeedRepository
	// AssetWebEvidence stores web assets' captures (RFC-081).
	AssetWebEvidence *postgres.AssetWebEvidenceRepository
	// EASMChange reads typed attack-surface changes and claims weekly digests (RFC-080).
	EASMChange *postgres.EASMChangeRepository

	// KEV Escalation
	KEVEscalator *postgres.KEVEscalator

	// Report Schedules
	ReportSchedule *postgres.ReportScheduleRepository

	// Per-user customizable dashboards (RFC-021, migration 000218)
	UserDashboard *postgres.UserDashboardRepository
	SavedView     *postgres.SavedViewRepository

	// Asset Dedup (RFC-001)
	AssetDedup *postgres.AssetDedupRepository

	// Asset identity model: identifiers each asset was seen with
	AssetIdentifier       *postgres.AssetIdentifierRepository
	AssetIdentityBackfill *postgres.AssetIdentityBackfillRepository

	// Priority Classification (RFC-004)
	PriorityRule  *postgres.PriorityRuleRepository
	PriorityAudit *postgres.PriorityAuditRepository
	EPSSAdapter   *postgres.EPSSAdapter
	KEVAdapter    *postgres.KEVAdapter

	// Indicators of Compromise (B6 runtime loop, migration 000156)
	IOC *postgres.IOCRepository

	// Validation evidence (CTEM Stage-4, migration 000178)
	ValidationEvidence      *postgres.ValidationEvidenceRepository
	FindingRetest           *postgres.FindingRetestRepository
	FindingEvidence         *postgres.FindingEvidenceRepository
	FindingSLARestart       *postgres.FindingSLARestartRepository
	FindingAcceptanceExpiry *postgres.FindingAcceptanceExpiryRepository

	// Runtime-telemetry reads for Stage-4 detection correlation
	// (migration 000203)
	TelemetryProbe *postgres.TelemetryProbeRepository

	// SCIM provisioning bearer tokens (RFC-009, migration 000179)
	ScimToken *postgres.ScimTokenRepository

	// SCIM groups (RFC-009 Phase 9c, migration 000180)
	ScimGroup *postgres.ScimGroupRepository

	// SAML SP config (RFC-009 Phase 9d, migration 000182)
	SAMLProvider *postgres.SAMLProviderRepository

	// Admin-console SSO changes awaiting an owner (RFC-022, migration 000273)
	SSOChange *postgres.SSOChangeRepository
}

// NewRepositories initializes all repositories.
func NewRepositories(db *postgres.DB) *Repositories {
	r := newRepositories(db)
	r.AssetIdentifier = postgres.NewAssetIdentifierRepository(db, r.Asset)
	r.AssetIdentityBackfill = postgres.NewAssetIdentityBackfillRepository(db)
	return r
}

func newRepositories(db *postgres.DB) *Repositories {
	return &Repositories{
		// Core
		User:   postgres.NewUserRepository(db),
		Tenant: postgres.NewTenantRepository(db),
		Audit:  postgres.NewAuditRepository(db),

		// Assets & Components
		Asset:                   postgres.NewAssetRepository(db),
		RepoExt:                 postgres.NewRepositoryExtensionRepository(db),
		RepoIdentity:            postgres.NewRepositoryIdentityRepository(db),
		Component:               postgres.NewComponentRepository(db),
		VEXStatement:            postgres.NewVEXStatementRepository(db),
		LicensePolicy:           postgres.NewLicensePolicyRepository(db),
		AssetGroup:              postgres.NewAssetGroupRepository(db),
		AssetType:               postgres.NewAssetTypeRepository(db),
		AssetTypeCat:            postgres.NewAssetTypeCategoryRepository(db),
		ScopeTarget:             postgres.NewScopeTargetRepository(db),
		ScopeExcl:               postgres.NewScopeExclusionRepository(db),
		AssetService:            postgres.NewAssetServiceRepository(db), // CTEM: Network services
		WebEndpoint:             postgres.NewWebEndpointRepository(db),
		Software:                postgres.NewSoftwareRepository(db),
		CVECorpus:               postgres.NewCVECorpusRepository(db),
		SoftwareMatch:           postgres.NewSoftwareMatchRepository(db),
		AssetAttributeSources:   postgres.NewAssetAttributeSourceRepository(db),
		AssetFreshness:          postgres.NewAssetFreshnessRepository(db),
		AssetCoverage:           postgres.NewAssetCoverageRepository(db),
		AssetWildcardDNS:        postgres.NewAssetWildcardDNSRepository(db),
		AssetEnrichmentRequests: postgres.NewAssetEnrichmentRequestRepository(db),
		AssetChangeEvents:       postgres.NewAssetChangeEventRepository(db),
		APISpec:                 postgres.NewAPISpecRepository(db),
		AssetStateHistory:       postgres.NewAssetStateHistoryRepository(db),      // CTEM: State change audit
		AssetRelationship:       postgres.NewAssetRelationshipRepository(db),      // CTEM: Asset topology graph
		RelationshipSuggestion:  postgres.NewRelationshipSuggestionRepository(db), // CTEM: Relationship suggestions
		ThreatModel:             postgres.NewThreatModelRepository(db),            // CTEM: Continuous threat models
		AttackerProfileReader:   postgres.NewAttackerProfileReader(db),            // CTEM: Attacker profiles (generation input)

		// Vulnerabilities & Findings
		Vulnerability:    postgres.NewVulnerabilityRepository(db),
		Finding:          postgres.NewFindingRepository(db),
		FindingComment:   postgres.NewFindingCommentRepository(db),
		CommentReaction:  postgres.NewCommentReactionRepository(db),
		FindingApproval:  postgres.NewFindingApprovalRepository(db),
		FindingActivity:  postgres.NewFindingActivityRepository(db),
		AITriage:         postgres.NewAITriageRepository(db),              // AI-powered vulnerability triage
		AITriageBudget:   postgres.NewAITriageBudgetRepository(db),        // RFC-008 monthly LLM token budget
		DataFlow:         postgres.NewDataFlowRepository(db),              // Data flow traces
		FindingSource:    postgres.NewFindingSourceRepository(db),         // Finding source configuration
		FindingSourceCat: postgres.NewFindingSourceCategoryRepository(db), // Finding source categories

		// Exposures & Threat Intel
		Exposure:             postgres.NewExposureRepository(db),
		ExposureStateHistory: postgres.NewExposureStateHistoryRepository(db),
		ThreatIntel:          postgres.NewThreatIntelRepository(db),
		CTEMID:               postgres.NewCTEMIDRepository(db),

		// Dashboard & Branch
		Dashboard: postgres.NewDashboardRepository(db.DB),
		Branch:    postgres.NewBranchRepository(db),

		// SLA & Integration
		// Pentest
		PentestCampaign:       postgres.NewPentestCampaignRepository(db),
		PentestCampaignMember: postgres.NewPentestCampaignMemberRepository(db),
		PentestSignoff:        postgres.NewPentestCampaignSignoffRepository(db),
		PentestSecret:         postgres.NewPentestCampaignSecretRepository(db),
		PentestRetest:         postgres.NewPentestRetestRepository(db),
		PentestTemplate:       postgres.NewPentestTemplateRepository(db),
		PentestReport:         postgres.NewPentestReportRepository(db),
		PentestReportTemplate: postgres.NewPentestReportTemplateRepository(db),
		PentestChecklistTpl:   postgres.NewPentestChecklistTemplateRepository(db),
		PentestChecklist:      postgres.NewPentestCampaignChecklistRepository(db),

		// Attachments
		Attachment: postgres.NewAttachmentRepository(db),

		// Compliance
		ComplianceFramework:  postgres.NewComplianceFrameworkRepository(db),
		ComplianceControl:    postgres.NewComplianceControlRepository(db),
		ComplianceAssessment: postgres.NewComplianceAssessmentRepository(db),
		ComplianceMapping:    postgres.NewComplianceMappingRepository(db),

		// Attack Simulation & Control Testing
		Simulation:    postgres.NewSimulationRepository(db),
		SimulationRun: postgres.NewSimulationRunRepository(db),
		ControlTest:   postgres.NewControlTestRepository(db),

		// Threat Actor Intelligence
		ThreatActor: postgres.NewThreatActorRepository(db),

		// Remediation Campaigns
		RemediationCampaign:       postgres.NewRemediationCampaignRepository(db),
		RemediationCampaignTicket: postgres.NewRemediationCampaignTicketRepository(db),
		TicketMapping:             postgres.NewTicketMappingRepository(db),
		TicketLink:                postgres.NewTicketLinkRepository(db),
		FindingRemediationKey:     postgres.NewFindingRemediationKeyRepository(db),

		// Business Units
		BusinessUnit: postgres.NewBusinessUnitRepository(db),

		SLA:         postgres.NewSLAPolicyRepository(db),
		Integration: postgres.NewIntegrationRepository(db),
		// IntegrationSCMExt and IntegrationNotificationExt initialized after Integration

		Outbox:       postgres.NewOutboxRepository(db),
		OutboxEvent:  postgres.NewOutboxEventRepository(db),
		Notification: postgres.NewNotificationRepository(db),

		// Sensors & Commands
		Sensor:                 postgres.NewSensorRepository(db),
		SensorAPIKey:           postgres.NewSensorAPIKeyRepository(db),
		SensorSigningKey:       postgres.NewSensorSigningKeyRepository(db),
		SensorPairing:          postgres.NewSensorPairingRepository(db),
		SensorGrant:            postgres.NewSensorGrantRepository(db),
		CollectorAsset:         postgres.NewCollectorAssetRepository(db),
		SensorReach:            postgres.NewSensorReachRepository(db),
		SensorEvent:            postgres.NewSensorEventRepository(db),
		CommandEvent:           postgres.NewCommandEventRepository(db),
		SensorHeartbeatHistory: postgres.NewSensorHeartbeatHistoryRepository(db),
		CommandLog:             postgres.NewCommandLogRepository(db),
		Command:                postgres.NewCommandRepository(db),
		ToolDurationStats:      postgres.NewToolDurationStatsRepository(db),
		SensorContentPolicy:    postgres.NewSensorContentPolicyRepository(db),
		SensorResult:           postgres.NewSensorResultRepository(db),
		IngestJob:              postgres.NewIngestJobRepository(db),
		IngestReport:           postgres.NewIngestReportRepository(db),

		// Scan coverage rotation (RFC-007)
		ScanCoverage: postgres.NewScanCoverageRepository(db),

		// Scan zones (RFC-023)
		ScanZone:            postgres.NewScanZoneRepository(db),
		ScanWindowPolicy:    postgres.NewScanWindowPolicyRepository(db),
		ScanWindowOverride:  postgres.NewScanWindowOverrideRepository(db),
		ScanWindowAsset:     postgres.NewScanWindowAssetRepository(db),
		ContentPack:         postgres.NewContentPackRepository(db),
		PlatformContentPack: postgres.NewPlatformContentPackRepository(db),

		// Scanning
		ScanProfile:      postgres.NewScanProfileRepository(db),
		Tool:             postgres.NewToolRepository(db),
		ToolCategory:     postgres.NewToolCategoryRepository(db),
		Capability:       postgres.NewCapabilityRepository(db),
		ToolCapability:   postgres.NewToolCapabilityRepository(db),
		TenantToolConfig: postgres.NewTenantToolConfigRepository(db),
		Scan:             postgres.NewScanRepository(db),
		ScanSelector:     postgres.NewScanSelectorRepository(db),
		ScannerTemplate:  postgres.NewScannerTemplateRepository(db),
		TemplateSource:   postgres.NewTemplateSourceRepository(db),
		SecretStore:      postgres.NewSecretStoreRepository(db),

		// ScanRuns
		ScanWorkflow:     postgres.NewScanWorkflowRepository(db),
		ScanRun:          postgres.NewScanRunRepository(db),
		ScanWorkflowStep: postgres.NewScanWorkflowStepRepository(db),
		StepRun:          postgres.NewStepRunRepository(db),

		// Workflows
		Workflow:        postgres.NewAutomationRepository(db),
		WorkflowNode:    postgres.NewAutomationNodeRepository(db),
		WorkflowEdge:    postgres.NewAutomationEdgeRepository(db),
		WorkflowRun:     postgres.NewAutomationRunRepository(db),
		WorkflowNodeRun: postgres.NewAutomationRunStepRepository(db),

		// Suppressions
		Suppression:        postgres.NewSuppressionRepository(db),
		FindingCorrelation: postgres.NewFindingCorrelationRepository(db),

		// Access Control
		Group:             postgres.NewGroupRepository(db),
		GroupRoleBinding:  postgres.NewGroupRoleBindingRepository(db),
		ServiceAccount:    postgres.NewServiceAccountRepository(db),
		AccessControl:     postgres.NewAccessControlRepository(db),
		DataScope:         postgres.NewDataScopeRepository(db),
		MemberLifecycle:   postgres.NewMemberLifecycleRepository(db),
		OwnershipTransfer: postgres.NewOwnershipTransferRepository(db),
		Role:              postgres.NewRoleRepository(db),
		RolePermission:    postgres.NewPermissionRepository(db),

		// Session (raw *sql.DB required)
		Session:      postgres.NewSessionRepository(db.DB),
		RefreshToken: postgres.NewRefreshTokenRepository(db.DB),
		UserMFA:      postgres.NewUserMFARepository(db),

		// Admin (Platform Admin)
		Admin:           postgres.NewAdminRepository(db),
		SignupPolicy:    postgres.NewSignupPolicyRepository(db),
		PlatformSetting: postgres.NewPlatformSettingRepository(db),
		ScanPolicy:      postgres.NewScanPolicyRepository(db),
		ScanApproval:    postgres.NewScanApprovalRepository(db),
		AccessRequest:   postgres.NewAccessRequestRepository(db),
		Plan:            postgres.NewPlanRepository(db),
		IdleLifecycle:   postgres.NewIdleLifecycleRepository(db),
		AdminAuditLog:   postgres.NewAuditLogRepository(db),
		AdminOrg:        postgres.NewAdminOrganizationRepository(db),
		AdminConsole:    postgres.NewAdminConsoleRepository(db),
		PlatformIdP:     postgres.NewPlatformIdPRepository(db),

		// Target Mappings
		TargetMapping: postgres.NewTargetMappingRepository(db),

		// API Keys & Webhooks
		APIKey:   postgres.NewAPIKeyRepository(db),
		MCPOAuth: postgres.NewMCPOAuthRepository(db),

		// Licensing (modules from database)
		Module:       postgres.NewModuleRepository(db),
		TenantModule: postgres.NewTenantModuleRepository(db),

		// SSO Identity Providers
		IdentityProvider: postgres.NewIdentityProviderRepository(db),
		UserIdentity:     postgres.NewUserIdentityRepository(db),
		OrgTrust:         postgres.NewOrgTrustRepository(db),
		VerifiedDomain:   postgres.NewVerifiedDomainRepository(db),
		CTMonitorState:   postgres.NewCTMonitorStateRepository(db),
		Attribution:      postgres.NewAttributionRepository(db),
		EASMDNS:          postgres.NewEASMDNSRepository(db),
		VerifiedNames:    postgres.NewVerifiedDomainNameRepository(db),
		CIRun:            postgres.NewCIRunRepository(db),
		CodeScan:         postgres.NewCodeScanRepository(db),
		SCMApp:           postgres.NewSCMAppInstallationRepository(db),
		EASMSummary:      postgres.NewEASMSummaryRepository(db),
		EASMLookalike:    postgres.NewEASMLookalikeRepository(db),
		EASMNetworkSeed:  postgres.NewEASMNetworkSeedRepository(db),
		AssetWebEvidence: postgres.NewAssetWebEvidenceRepository(db),
		EASMChange:       postgres.NewEASMChangeRepository(db),

		// KEV Escalation
		KEVEscalator: postgres.NewKEVEscalator(db),

		// Report Schedules
		ReportSchedule: postgres.NewReportScheduleRepository(db),

		// Per-user customizable dashboards (RFC-021)
		UserDashboard: postgres.NewUserDashboardRepository(db),
		SavedView:     postgres.NewSavedViewRepository(db),

		// Asset Dedup (RFC-001)
		AssetDedup: postgres.NewAssetDedupRepository(db),

		// Priority Classification (RFC-004)
		PriorityRule:  postgres.NewPriorityRuleRepository(db),
		PriorityAudit: postgres.NewPriorityAuditRepository(db),

		// B6 runtime loop — IOC catalogue + match log (migration 000156).
		IOC: postgres.NewIOCRepository(db),

		// Validation evidence (CTEM Stage-4, migration 000178).
		ValidationEvidence:      postgres.NewValidationEvidenceRepository(db),
		FindingRetest:           postgres.NewFindingRetestRepository(db),
		FindingEvidence:         postgres.NewFindingEvidenceRepository(db),
		FindingSLARestart:       postgres.NewFindingSLARestartRepository(db),
		FindingAcceptanceExpiry: postgres.NewFindingAcceptanceExpiryRepository(db),

		// Runtime-telemetry reads for detection correlation (migration 000203).
		TelemetryProbe: postgres.NewTelemetryProbeRepository(db),

		// SCIM provisioning bearer tokens (RFC-009, migration 000179).
		ScimToken: postgres.NewScimTokenRepository(db),

		// SCIM groups (RFC-009 Phase 9c, migration 000180).
		ScimGroup: postgres.NewScimGroupRepository(db),

		// SAML SP config (RFC-009 Phase 9d, migration 000182).
		SAMLProvider: postgres.NewSAMLProviderRepository(db),

		// Admin-console SSO changes awaiting an owner (migration 000273).
		SSOChange: postgres.NewSSOChangeRepository(db),
	}
}

// InitIntegrationExtensions initializes integration extension repositories.
// Must be called after NewRepositories.
func (r *Repositories) InitIntegrationExtensions(db *postgres.DB) {
	r.IntegrationSCMExt = postgres.NewIntegrationSCMExtensionRepository(db, r.Integration)
	r.IntegrationNotificationExt = postgres.NewIntegrationNotificationExtensionRepository(db, r.Integration)
}
