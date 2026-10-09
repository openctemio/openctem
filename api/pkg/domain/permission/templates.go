package permission

// RoleTemplate is a starting point for a custom role, shaped after one kind of
// person who works in a CTEM program. Creating a role from a template goes
// through the normal custom-role path (POST /api/v1/roles): the creator may
// only include permissions they hold themselves, admin-only permissions are
// refused, and the role is theirs to edit afterwards. A template grants
// nothing by itself.
//
// Templates are composable: a person may hold several roles, and their
// permissions are the union. Data scope (which assets they see) never comes
// from a role, except for HasFullDataAccess: it comes from their teams.
type RoleTemplate struct {
	ID          string
	Name        string
	Description string
	// Personas the template is meant for, in plain words.
	Personas []string
	// HasFullDataAccess: the role sees every asset. Only owners may create
	// such a role, with step-up; keep it to people who must see everything.
	HasFullDataAccess bool
	Permissions       []Permission
}

// readCore is what every template that works with the program reads.
var readCore = []Permission{
	DashboardRead, SettingsRead, TeamRead, MembersRead,
	AssetsRead, AssetGroupsRead, ComponentsRead,
	FindingsRead, ExposuresRead, VulnerabilitiesRead, RemediationRead,
}

func join(parts ...[]Permission) []Permission {
	seen := map[Permission]bool{}
	var out []Permission
	for _, p := range parts {
		for _, x := range p {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// roleTemplates, in display order.
var roleTemplates = []RoleTemplate{
	{
		ID:   "program-lead",
		Name: "CTEM program lead",
		Description: "Runs the program: scopes cycles, sets priority rules and SLAs, approves risk acceptance " +
			"and suppressions, approves scope changes and reports to leadership. Does not administer members, " +
			"sensors or integrations.",
		Personas:          []string{"CISO or security leader", "CTEM program manager"},
		HasFullDataAccess: true,
		Permissions: join(readCore, []Permission{
			DashboardAggregate,
			CTEMCyclesRead, CTEMCyclesWrite, AttackerProfilesRead, AttackerProfilesWrite,
			BusinessServicesRead, BusinessServicesWrite, CompensatingControlsRead, CompensatingControlsWrite,
			PriorityRulesRead, PriorityRulesWrite, VerificationChecklistsRead,
			SLARead, SLAWrite,
			FindingsApprove, FindingsComment, SuppressionsRead, SuppressionsApprove,
			ScopeRead, ScopeApprove, ScopeExclusionsApprove,
			CredentialsRead, ThreatIntelRead, ScansRead,
			PentestCampaignsRead, PentestFindingsRead, ComplianceFrameworksRead, ComplianceAssessmentsRead,
			ReportsRead, ReportsWrite, FindingsExport,
		}),
	},
	{
		ID:   "security-analyst",
		Name: "Security analyst",
		Description: "Triages findings and exposures in their scope: severity, status, duplicates, assignment, " +
			"comments and evidence; verifies fixes and requests retests. May request risk acceptance but " +
			"never approves it.",
		Personas: []string{"Security operations analyst", "Exposure triage analyst"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsSeverity,
			FindingsTriage, FindingsStatus, FindingsAssign, FindingsBulkUpdate, FindingsVerify,
			ExposuresWrite, ExposuresTriage, SuppressionsRead, SuppressionsWrite,
			CredentialsRead, WorkflowsRead,
			ScansRead, ScansExecute, ScanProfilesRead,
			ThreatIntelRead, AITriageRead, AITriageTrigger,
			CTEMCyclesRead, BusinessServicesRead, CompensatingControlsRead, VerificationChecklistsRead,
			VerificationChecklistsWrite, SLARead, ScopeRead, ReportsRead,
		}),
	},
	{
		ID:   "vulnerability-manager",
		Name: "Vulnerability manager",
		Description: "Owns the remediation backlog: routes work to owners with assignment rules, runs " +
			"remediation campaigns, schedules scans and reports on SLA performance. Does not approve " +
			"risk acceptance.",
		Personas: []string{"Vulnerability management lead", "Remediation coordinator"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsSeverity,
			FindingsTriage, FindingsStatus, FindingsAssign, FindingsBulkUpdate, FindingsVerify,
			FindingsExport,
			ExposuresWrite, ExposuresTriage, SuppressionsRead, SuppressionsWrite,
			RemediationWrite, WorkflowsRead, WorkflowsWrite,
			AssignmentRulesRead, AssignmentRulesWrite,
			ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScanProfilesWrite, ScanWorkflowsRead,
			ScannerTemplatesRead, ToolsRead,
			SLARead, PriorityRulesRead, CTEMCyclesRead, BusinessServicesRead, CompensatingControlsRead,
			VerificationChecklistsRead, VerificationChecklistsWrite,
			ThreatIntelRead, ScopeRead, ReportsRead, ReportsWrite,
		}),
	},
	{
		ID:   "remediation-owner",
		Name: "Remediation owner",
		Description: "Fixes what is assigned to their team: comments, remediation steps, tickets and " +
			"marking a fix applied. Requests risk acceptance with a justification. Cannot re-score " +
			"severity, verify their own fix, approve, delete or change scans.",
		Personas: []string{"Asset or system owner", "IT and infrastructure engineer", "Developer", "Engineering manager"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsStatus, FindingsFixApply,
			VerificationChecklistsRead, SLARead, ScansRead,
		}),
	},
	{
		ID:   "appsec-engineer",
		Name: "AppSec engineer",
		Description: "Runs code and dependency scanning for their repositories, triages application " +
			"findings and works the CI gate with developers.",
		Personas: []string{"Application security engineer", "DevSecOps engineer"},
		Permissions: join(readCore, []Permission{
			ComponentsWrite, AssetsWrite,
			FindingsWrite, FindingsComment, FindingsSeverity, FindingsTriage, FindingsStatus, FindingsAssign, FindingsVerify,
			SuppressionsRead, SuppressionsWrite,
			ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScanProfilesWrite,
			ScanWorkflowsRead, ToolsRead, ScannerTemplatesRead,
			SCMConnectionsRead, CIRead, SLARead, ReportsRead,
		}),
	},
	{
		ID:   "scan-operator",
		Name: "Scan operator",
		Description: "Schedules and runs scans and scan workflows against approved scope and watches " +
			"their results. Cannot change scope, sensors, templates or findings.",
		Personas: []string{"Scanning operations engineer"},
		Permissions: join(readCore, []Permission{
			ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScanProfilesWrite,
			ScanWorkflowsRead, ScanWorkflowsWrite, ScannerTemplatesRead, TemplateSourcesRead,
			ToolsRead, TenantToolsRead, ContentPacksRead,
			SensorsRead, CommandsRead, ScanZonesRead, ScopeRead,
		}),
	},
	{
		ID:   "validation-engineer",
		Name: "Validation engineer",
		Description: "Proves exploitability: runs pentest campaigns, attack simulations and control " +
			"tests, records validated findings and retests fixes. Cannot approve risk or change scope.",
		Personas: []string{"Red team or internal penetration tester", "Breach and attack simulation engineer", "Purple team"},
		Permissions: join(readCore, []Permission{
			PentestRead, PentestWrite,
			PentestCampaignsRead, PentestCampaignsWrite, PentestFindingsRead, PentestFindingsWrite,
			PentestRetestsRead, PentestRetestsWrite, PentestTemplatesRead, PentestTemplatesWrite, PentestReportsWrite,
			FindingsWrite, FindingsComment, FindingsSeverity, FindingsVerify,
			ScansRead, ScansExecute, ScanProfilesRead, ScopeRead,
			AttackerProfilesRead, CompensatingControlsRead, VerificationChecklistsRead, ThreatIntelRead,
		}),
	},
	{
		ID:   "external-tester",
		Name: "External tester",
		Description: "A vendor penetration tester on an engagement: reads and writes findings of the " +
			"campaigns they are a member of and their retests. Pair with an external membership that " +
			"has an end date and a team that holds only the engagement's assets.",
		Personas: []string{"Penetration testing vendor", "Contracted red team"},
		Permissions: []Permission{
			DashboardRead, TeamRead,
			AssetsRead,
			PentestCampaignsRead, PentestFindingsRead, PentestFindingsWrite, PentestRetestsRead, PentestRetestsWrite,
			PentestTemplatesRead, ScopeRead,
		},
	},
	{
		ID:   "threat-intel-analyst",
		Name: "Threat intelligence analyst",
		Description: "Maintains attacker profiles, threat actors and indicators, and records external " +
			"exposures such as leaked credentials and lookalike domains.",
		Personas: []string{"Threat intelligence analyst", "Digital risk and brand protection"},
		Permissions: join(readCore, []Permission{
			ThreatIntelRead, ThreatIntelWrite, AttackerProfilesRead, AttackerProfilesWrite,
			ExposuresWrite, ExposuresTriage, CredentialsRead, CredentialsWrite,
			FindingsWrite, FindingsComment, FindingsSeverity, FindingsTriage, ScopeRead, ReportsRead,
		}),
	},
	{
		ID:   "risk-approver",
		Name: "Risk approver",
		Description: "Governance: approves or rejects risk acceptance, false positives and suppression " +
			"rules, and maintains compliance assessments. Holds no fix or triage permission, so the " +
			"person who asks is never the person who approves.",
		Personas: []string{"GRC and risk manager", "Compliance manager"},
		Permissions: join(readCore, []Permission{
			FindingsApprove, FindingsComment, SuppressionsRead, SuppressionsApprove,
			ComplianceFrameworksRead, ComplianceAssessmentsRead, ComplianceAssessmentsWrite,
			ComplianceMappingsRead, ComplianceMappingsWrite,
			SLARead, CTEMCyclesRead, BusinessServicesRead, CompensatingControlsRead, ReportsRead, ReportsWrite,
		}),
	},
	{
		ID:   "auditor",
		Name: "Auditor",
		Description: "Read-only evidence for an audit: every asset, finding, decision and the audit " +
			"log, plus exports. Changes nothing. Give it to internal or external auditors with an " +
			"access end date.",
		Personas:          []string{"Internal or external auditor"},
		HasFullDataAccess: true,
		Permissions: join(readCore, []Permission{
			AuditRead, FindingsExport, SuppressionsRead, CredentialsRead,
			ScansRead, ScopeRead, SLARead, PriorityRulesRead, CTEMCyclesRead,
			BusinessServicesRead, CompensatingControlsRead, VerificationChecklistsRead,
			ComplianceFrameworksRead, ComplianceAssessmentsRead, ComplianceMappingsRead,
			PentestCampaignsRead, PentestFindingsRead, PentestRetestsRead,
			RolesRead, GroupsRead, ReportsRead,
		}),
	},
	{
		ID:   "executive",
		Name: "Executive viewer",
		Description: "Dashboards, CTEM cycle outcomes and reports for leadership, inside the data " +
			"scope of their teams. Less than the built-in viewer: no configuration, scans or member lists.",
		Personas: []string{"Executive or board member", "Business unit leader"},
		Permissions: []Permission{
			DashboardRead, TeamRead,
			AssetsRead, FindingsRead, ExposuresRead, RemediationRead,
			CTEMCyclesRead, BusinessServicesRead, SLARead, ReportsRead,
		},
	},
}

// RoleTemplates returns the custom-role templates (a fresh copy).
func RoleTemplates() []RoleTemplate {
	out := make([]RoleTemplate, len(roleTemplates))
	for i, t := range roleTemplates {
		t.Permissions = append([]Permission(nil), t.Permissions...)
		t.Personas = append([]string(nil), t.Personas...)
		out[i] = t
	}
	return out
}

// RoleTemplateByID returns one template.
func RoleTemplateByID(id string) (RoleTemplate, bool) {
	for _, t := range RoleTemplates() {
		if t.ID == id {
			return t, true
		}
	}
	return RoleTemplate{}, false
}
