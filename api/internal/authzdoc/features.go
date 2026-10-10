package authzdoc

import "strings"

// Feature is one page of the authorization reference: a product area and
// the routes that belong to it.
type Feature struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Stages      []string `json:"stages,omitempty"` // CTEM stages the feature serves
	// Registers are the route-registering functions whose routes belong here.
	Registers []string `json:"-"`
	// Prefixes claim routes registered inline (outside a register function).
	Prefixes []string `json:"-"`
}

// CTEM stages.
const (
	StageScoping        = "scoping"
	StageDiscovery      = "discovery"
	StagePrioritization = "prioritization"
	StageValidation     = "validation"
	StageMobilization   = "mobilization"
)

// Features lists every feature in display order. A new route-registering
// function must be listed in exactly one feature; TestEveryRouteHasAFeature
// fails otherwise.
var Features = []Feature{
	{
		ID: "findings", Title: "Findings",
		Description: "Vulnerabilities and other findings: triage, status, assignment, approvals, comments, evidence, retests and imports.",
		Stages:      []string{StageDiscovery, StagePrioritization, StageMobilization},
		Registers: []string{
			"registerVulnerabilityRoutes", "registerFindingActivityRoutes", "registerFindingEvidenceItemRoutes",
			"registerFindingImportRoutes", "registerFindingRetestRoutes", "registerFindingSourceRoutes",
			"registerAITriageRoutes", "registerAttachmentRoutes", "registerSavedViewRoutes",
		},
		Prefixes: []string{"/api/v1/verification-checklists"},
	},
	{
		ID: "exposures", Title: "Exposures and leaked credentials",
		Description: "Non-vulnerability exposures (misconfiguration, identity, leaked credentials, lookalike domains) and the leaked-credential register.",
		Stages:      []string{StageDiscovery, StagePrioritization},
		Registers:   []string{"registerExposureRoutes", "registerCredentialRoutes", "registerCTEMIDRoutes"},
	},
	{
		ID: "assets", Title: "Assets and inventory",
		Description: "The asset inventory: assets, groups, types, owners, identifiers, relationships, services, components, branches, API specs, web endpoints and history.",
		Stages:      []string{StageScoping, StageDiscovery},
		Registers: []string{
			"registerAssetRoutes", "registerAssetGroupRoutes", "registerAssetTypeRoutes", "registerAssetOwnerRoutes",
			"registerAssetIdentifierRoutes", "registerAssetAttributionRoutes", "registerAssetImportRoutes",
			"registerAssetDedupRoutes", "registerAssetRelationshipRoutes", "registerRelationshipSuggestionRoutes",
			"registerAssetServiceRoutes", "registerAssetStateHistoryRoutes", "registerAssetSoftwareRoutes", "registerComponentRoutes", "registerVEXStatementRoutes",
			"registerBranchRoutes", "registerAPISpecRoutes", "registerWebEndpointRoutes",
		},
	},
	{
		ID: "attack-surface", Title: "Attack surface and EASM",
		Description: "External attack surface management: discovery candidates, verified domains, sweeps, attack paths and the scoping summary.",
		Stages:      []string{StageScoping, StageDiscovery, StagePrioritization},
		Registers: []string{
			"registerAttackSurfaceRoutes", "registerEASMRoutes", "registerEASMSettingsRoutes",
			"registerEASMVerifiedDomainRoutes", "registerScopingRoutes",
		},
	},
	{
		ID: "scope", Title: "Scope",
		Description: "What the organization may scan: scope targets, exclusions, approvals and scope settings.",
		Stages:      []string{StageScoping},
		Registers:   []string{"registerScopeRoutes", "registerScopeLetterRoutes"},
	},
	{
		ID: "programs", Title: "Bug-bounty programs",
		Description: "Programs the organization tests under their published rules: import with an attestation, re-import, pause, resume and end (RFC-065).",
		Stages:      []string{StageScoping},
		Registers:   []string{"registerProgramRoutes"},
	},
	{
		ID: "ctem-program", Title: "CTEM program",
		Description: "The program layer: CTEM cycles, business services and units, attacker profiles, compensating controls and threat models.",
		Stages:      []string{StageScoping, StagePrioritization},
		Registers: []string{
			"registerCTEMCycleRoutes", "registerBusinessServiceRoutes", "registerBusinessUnitRoutes",
			"registerAttackerProfileRoutes", "registerCompensatingControlRoutes", "registerThreatModelRoutes",
		},
	},
	{
		ID: "prioritization", Title: "Prioritization and SLAs",
		Description: "Priority rules and SLA policies that decide what is fixed first and by when.",
		Stages:      []string{StagePrioritization},
		Registers:   []string{"registerPriorityRuleRoutes", "registerSLARoutes"},
	},
	{
		ID: "remediation", Title: "Remediation and automation",
		Description: "Remediation campaigns, suppression and exception rules, assignment rules and automation workflows.",
		Stages:      []string{StageMobilization},
		Registers: []string{
			"registerRemediationCampaignRoutes", "registerSuppressionRoutes", "registerAssignmentRuleRoutes",
			"registerWorkflowRoutes",
		},
	},
	{
		ID: "scans", Title: "Scans and workflows",
		Description: "Scans, scan runs and workflows, profiles, tools, templates, content packs, the secret store and freeze windows.",
		Stages:      []string{StageDiscovery, StageValidation},
		Registers: []string{
			"registerScanRoutes", "registerScanWorkflowRoutes", "registerScanProfileRoutes", "registerScanWindowRoutes",
			"registerScannerTemplateRoutes", "registerTemplateSourceRoutes", "registerContentPackRoutes", "registerPlatformContentPackRoutes",
			"registerToolRoutes", "registerToolCategoryRoutes", "registerCapabilityRoutes", "registerSecretStoreRoutes",
			"registerPlatformScanningRoutes", "registerCommandRoutes",
		},
	},
	{
		ID: "sensors", Title: "Sensors and scan zones",
		Description: "The sensor fleet: registration, pairing and grants, scan zones and the sensor protocol.",
		Stages:      []string{StageDiscovery},
		Registers: []string{
			"registerSensorManagementRoutes", "registerSensorPairingRoutes", "registerScanZoneRoutes",
			"registerFleetRoutes", "mountSensorV2",
		},
	},
	{
		ID: "ci", Title: "CI pipelines",
		Description: "CI runner identity, trust configurations, the central gate and its overrides.",
		Stages:      []string{StageDiscovery, StageMobilization},
		Registers:   []string{"registerCIRoutes"},
	},
	{
		ID: "pentest", Title: "Penetration testing",
		Description: "Pentest campaigns, their findings, retests, templates and reports. Campaign membership decides who sees a campaign.",
		Stages:      []string{StageValidation},
		Registers:   []string{"registerPentestRoutes"},
	},
	{
		ID: "validation", Title: "Validation and simulation",
		Description: "Exploitability validation, attack simulations and control tests.",
		Stages:      []string{StageValidation},
		Registers:   []string{"registerValidationRoutes", "registerSimulationRoutes"},
	},
	{
		ID: "threat-intel", Title: "Threat intelligence",
		Description: "EPSS, KEV, threat actors and indicators of compromise.",
		Stages:      []string{StagePrioritization},
		Registers:   []string{"registerThreatIntelRoutes", "registerThreatActorRoutes", "registerIOCRoutes"},
	},
	{
		ID: "compliance", Title: "Compliance",
		Description: "Compliance frameworks, assessments and control mappings.",
		Stages:      []string{StageMobilization},
		Registers:   []string{"registerComplianceRoutes"},
	},
	{
		ID: "dashboards-reports", Title: "Dashboards and reports",
		Description: "Dashboards, personal dashboards and scheduled reports.",
		Stages:      []string{StageMobilization},
		Registers:   []string{"registerDashboardRoutes", "registerUserDashboardRoutes", "registerReportScheduleRoutes"},
	},
	{
		ID: "integrations", Title: "Integrations and API keys",
		Description: "Ticketing, SCM, SIEM and notification integrations, inbound webhooks, the notification outbox and API keys.",
		Stages:      []string{StageMobilization},
		Registers: []string{
			"registerIntegrationRoutes", "registerIncomingWebhookRoutes", "registerOutboxRoutes", "registerAPIKeyRoutes",
		},
		Prefixes: []string{"/api/v1/webhooks/incoming"},
	},
	{
		ID: "access", Title: "Members, roles and teams",
		Description: "Members, invitations, roles, teams (access groups) and their data scope, trusted organizations and SCIM provisioning.",
		Registers: []string{
			"registerRoleRoutes", "registerGroupRoutes", "registerScopeRuleRoutes", "registerOrganizationMemberRoutes",
			"registerOrganizationTrustRoutes", "registerSCIMRoutes", "registerPermissionSyncRoutes",
			"registerServiceAccountRoutes",
		},
	},
	{
		ID: "organization", Title: "Organization settings and audit",
		Description: "The organization, its settings (security, SSO, evidence, retests, asset sources), plan and the audit log.",
		Registers: []string{
			"registerTenantRoutes", "registerAuditRoutes", "registerOrganizationPlanRoutes",
			"registerEvidenceSettingsRoutes", "registerRetestSettingsRoutes", "registerVulnMatchingSettingsRoutes", "registerLicensePolicySettingsRoutes",
			"registerAssetReconciliationSettingsRoutes",
		},
	},
	{
		ID: "mcp", Title: "MCP and AI clients",
		Description: "The MCP endpoint for AI clients, its OAuth authorization server, connections and organization policy.",
		Registers: []string{
			"registerMCPRoutes", "registerMCPOAuthRoutes", "registerMCPConnectionRoutes", "registerMCPSettingsRoutes",
			"registerMCPClientRoutes",
		},
	},
	{
		ID: "account", Title: "Sign-in and own account",
		Description: "Authentication, the caller's own account, notifications, platform announcements, bootstrap data and the real-time socket.",
		Registers: []string{
			"registerAuthRoutes", "registerUserRoutes", "registerNotificationRoutes", "registerBootstrapRoutes",
			"registerWebSocketRoutes", "registerAnnouncementRoute",
		},
	},
	{
		ID: "admin-console", Title: "Platform admin console",
		Description: "The platform operator's console. Its administrators are a separate realm and never members of an organization.",
		Registers:   []string{"registerAdminRoutes"},
	},
	{
		ID: "system", Title: "System endpoints",
		Description: "Health, metrics, version, API documentation and client error reports.",
		Registers: []string{
			"registerHealthRoutes", "registerDocsRoutes", "registerVersionRoute", "registerClientErrorRoute",
		},
	},
}

// FeatureOf returns the feature a route belongs to: an inline route by its
// path prefix, any other by the function that registers it.
func FeatureOf(r Route) (Feature, bool) {
	for _, f := range Features {
		for _, p := range f.Prefixes {
			if strings.HasPrefix(r.Path, p) && !strings.HasPrefix(r.Register, "register") {
				return f, true
			}
		}
	}
	for _, f := range Features {
		for _, reg := range f.Registers {
			if reg == r.Register {
				return f, true
			}
		}
	}
	return Feature{}, false
}
