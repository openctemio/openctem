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
	ID string
	// Version goes up by one whenever the template's permissions or full
	// data access change. A role created from a template records the version
	// and the permissions it took (roles.template_version,
	// roles.template_permissions), so a later change to the template never
	// changes that role: its editors see "update available" with the
	// difference and decide. TestRoleTemplates_VersionPinned fails when the
	// permissions change without a new version.
	Version     int
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

// validationWork is what a tester does in a validation exercise: campaigns,
// findings, retests, simulations and control tests, and the targeted scans
// that prove a finding (a run needs scans:write and scans:execute together).
var validationWork = []Permission{
	PentestRead, PentestWrite,
	PentestCampaignsRead, PentestCampaignsWrite, PentestFindingsRead, PentestFindingsWrite,
	PentestRetestsRead, PentestRetestsWrite, PentestTemplatesRead, PentestTemplatesWrite, PentestReportsWrite,
	FindingsWrite, FindingsComment, FindingsSeverity, FindingsVerify, FindingsRetestChecksWrite,
	ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScopeRead,
	AttackerProfilesRead, CompensatingControlsRead, VerificationChecklistsRead, ThreatIntelRead,
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
		ID:      "program-lead",
		Version: 3,
		Name:    "CTEM program lead",
		Description: "Runs the program: scopes cycles, sets priority rules and SLAs, approves risk acceptance " +
			"and suppressions, approves scope changes and scan runs that need approval, and reports to " +
			"leadership with organization dashboards. Does not administer members, sensors or integrations.",
		Personas:          []string{"CISO or security leader", "CTEM program manager"},
		HasFullDataAccess: true,
		Permissions: join(readCore, []Permission{
			DashboardsOrgView, DashboardsOrgManage,
			CTEMCyclesRead, CTEMCyclesWrite, AttackerProfilesRead, AttackerProfilesWrite,
			BusinessServicesRead, BusinessServicesWrite, CompensatingControlsRead, CompensatingControlsWrite,
			PriorityRulesRead, PriorityRulesWrite, VerificationChecklistsRead,
			SLARead, SLAWrite,
			FindingsApprove, FindingsComment, SuppressionsRead, SuppressionsApprove,
			// Accepting the risk of an exposure, or dismissing it, needs the
			// approver permission and exposure triage together.
			ExposuresTriage, FindingsViewsShare,
			ScopeRead, ScopeApprove, ScopeExclusionsApprove,
			CredentialsRead, ThreatIntelRead, ScansRead, ScansApprove,
			PentestCampaignsRead, PentestFindingsRead, ComplianceFrameworksRead, ComplianceAssessmentsRead,
			ReportsRead, ReportsWrite, FindingsExport,
		}),
	},
	{
		ID:      "security-analyst",
		Version: 4,
		Name:    "Security analyst",
		Description: "Triages findings and exposures in their scope: severity, status, duplicates, assignment, " +
			"comments and evidence; verifies fixes and requests retests. May request risk acceptance but " +
			"never approves it.",
		Personas: []string{"Security operations analyst", "Exposure triage analyst"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsSeverity,
			FindingsTriage, FindingsStatus, FindingsAssign, FindingsBulkUpdate, FindingsVerify, FindingsRetestChecksWrite,
			ExposuresWrite, ExposuresTriage, SuppressionsRead, SuppressionsWrite,
			CredentialsRead, AutomationsRead,
			ScansRead, ScanProfilesRead,
			ThreatIntelRead, AITriageRead, AITriageTrigger,
			CTEMCyclesRead, BusinessServicesRead, CompensatingControlsRead, VerificationChecklistsRead,
			VerificationChecklistsWrite, SLARead, ScopeRead, ReportsRead,
		}),
	},
	{
		ID:      "vulnerability-manager",
		Version: 4,
		Name:    "Vulnerability manager",
		Description: "Owns the remediation backlog: routes work to owners with assignment rules, runs " +
			"remediation campaigns, schedules scans and reports on SLA performance. Does not approve " +
			"risk acceptance.",
		Personas: []string{"Vulnerability management lead", "Remediation coordinator"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsSeverity,
			FindingsTriage, FindingsStatus, FindingsAssign, FindingsBulkUpdate, FindingsVerify, FindingsRetestChecksWrite,
			FindingsExport, FindingsViewsShare,
			ExposuresWrite, ExposuresTriage, SuppressionsRead, SuppressionsWrite,
			RemediationWrite, AutomationsRead, AutomationsWrite,
			AssignmentRulesRead, AssignmentRulesWrite,
			ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScanProfilesWrite, ScanWorkflowsRead,
			ScannerTemplatesRead, ToolsRead,
			SLARead, PriorityRulesRead, CTEMCyclesRead, BusinessServicesRead, CompensatingControlsRead,
			VerificationChecklistsRead, VerificationChecklistsWrite,
			ThreatIntelRead, ScopeRead, ReportsRead, ReportsWrite,
		}),
	},
	{
		ID:      "remediation-owner",
		Version: 2,
		Name:    "Remediation owner",
		Description: "Fixes what is assigned to their team: comments, remediation steps, tickets and " +
			"marking a fix applied. Requests risk acceptance with a justification. Follows the pentest " +
			"campaigns they are a client of. Cannot re-score severity, verify their own fix, approve, " +
			"delete or change scans.",
		Personas: []string{"Asset or system owner", "IT and infrastructure engineer", "Developer", "Engineering manager"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsStatus, FindingsFixApply,
			VerificationChecklistsRead, SLARead, ScansRead,
			// A campaign's client: published findings, comments and retest
			// requests of the campaigns they are a member of (membership
			// is checked on every campaign route).
			PentestCampaignsRead, PentestFindingsRead,
		}),
	},
	{
		ID:      "remediation-lead",
		Version: 1,
		Name:    "Remediation lead",
		Description: "Plans the fixes of their team: remediation tasks in their scope (create, split, merge, " +
			"tracker issue, mark fixed), assignment within the team and bulk status, besides everything a " +
			"remediation owner does. Cannot re-score severity, verify a fix, approve or change scans.",
		Personas: []string{"Engineering manager or tech lead", "Security champion in a product team"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsStatus, FindingsFixApply,
			FindingsAssign, FindingsBulkUpdate, RemediationWrite,
			VerificationChecklistsRead, SLARead, ScansRead, CIRead, ReportsRead,
			PentestCampaignsRead, PentestFindingsRead,
		}),
	},
	{
		ID:      "appsec-engineer",
		Version: 3,
		Name:    "AppSec engineer",
		Description: "Runs code and dependency scanning for their repositories, triages application " +
			"findings, and runs the CI gate: gate policies, expected scans and break-glass.",
		Personas: []string{"Application security engineer", "DevSecOps engineer"},
		Permissions: join(readCore, []Permission{
			ComponentsWrite, AssetsWrite,
			FindingsWrite, FindingsComment, FindingsSeverity, FindingsTriage, FindingsStatus, FindingsAssign, FindingsVerify, FindingsRetestChecksWrite,
			SuppressionsRead, SuppressionsWrite,
			ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScanProfilesWrite,
			ScanWorkflowsRead, ToolsRead, ScannerTemplatesRead,
			// Code host connections are listed under integrations: reading
			// them needs integrations:read as well.
			IntegrationsRead, SCMConnectionsRead, SLARead, ReportsRead, ScopeRead,
			AITriageRead, AITriageTrigger,
			// Runs the CI gate: gate policies and coverage expectations
			// (policy), and break-glass for one commit (override, with
			// step-up). Trust and code host connections issue upload
			// credentials and stay with administrators (scans:ci:write).
			CIRead, CIPolicy, CIOverride,
		}),
	},
	{
		ID:      "ci-integrator",
		Version: 2,
		Name:    "CI integrator",
		Description: "Keeps pipelines connected to the CI gate: reads CI runs, their gate results, " +
			"code host connections and scan profiles to troubleshoot an integration. Gate policies and " +
			"break-glass are AppSec's call; CI trust that issues upload credentials stays with administrators.",
		Personas: []string{"Platform or DevOps engineer", "Build and release engineer"},
		Permissions: []Permission{
			DashboardRead, TeamRead,
			AssetsRead, ComponentsRead, FindingsRead,
			ScansRead, ScanProfilesRead, ToolsRead,
			IntegrationsRead, SCMConnectionsRead, CIRead,
		},
	},
	{
		ID:      "scan-operator",
		Version: 2,
		Name:    "Scan operator",
		Description: "Schedules and runs scans and scan workflows against approved scope and watches " +
			"their results. Cannot change scope, sensors, templates or findings.",
		Personas: []string{"Scanning operations engineer"},
		Permissions: join(readCore, []Permission{
			ScansRead, ScansWrite, ScansExecute, ScanProfilesRead, ScanProfilesWrite,
			ScanWorkflowsRead, ScanWorkflowsWrite, ScannerTemplatesRead, ContentSourcesRead,
			ToolsRead, TenantToolsRead, ContentPacksRead, ContentRead,
			SensorsRead, CommandsRead, ScanZonesRead, ScopeRead,
		}),
	},
	{
		ID:      "sensor-operator",
		Version: 1,
		Name:    "Sensor operator",
		Description: "Watches the sensor fleet and its work: sensor health, scan zones and the commands " +
			"queued to sensors, and queues commands such as a restart or an update. Pairing, keys and " +
			"zones stay with administrators.",
		Personas: []string{"Infrastructure or network engineer who hosts sensors"},
		Permissions: []Permission{
			DashboardRead, TeamRead,
			SensorsRead, CommandsRead, CommandsWrite, ScanZonesRead,
			ScansRead, ToolsRead, ScopeRead,
		},
	},
	{
		ID:      "validation-engineer",
		Version: 3,
		Name:    "Validation engineer",
		Description: "Proves exploitability: runs pentest campaigns, attack simulations, control " +
			"tests and targeted scans, records validated findings and retests fixes. Cannot approve risk " +
			"or change scope.",
		Personas:    []string{"Red team or internal penetration tester", "Breach and attack simulation engineer", "Purple team"},
		Permissions: join(readCore, validationWork),
	},
	{
		ID:      "validation-lead",
		Version: 1,
		Name:    "Validation lead",
		Description: "Leads the validation program on top of a validation engineer's work: maintains " +
			"methodology checklists and the attacker profiles exercises emulate, and requests the scope and " +
			"authorization letters of an engagement. Never approves scope or risk.",
		Personas: []string{"Penetration testing or red team lead", "Offensive security manager"},
		Permissions: join(readCore, validationWork, []Permission{
			PentestChecklistsManage, AttackerProfilesWrite,
			// Requests scope entries, exclusions and authorization letters;
			// widening scope still needs an approver (scope:approve).
			ScopeWrite,
			CTEMCyclesRead, ReportsRead,
		}),
	},
	{
		ID:      "detection-engineer",
		Version: 1,
		Name:    "Detection engineer",
		Description: "Turns validation results into defenses: reads simulations, control tests and the " +
			"campaigns they observe, and records compensating controls and their test results. Does not " +
			"run attacks or scans and does not change findings.",
		Personas: []string{"Detection engineer", "SOC or blue team analyst", "Purple team defender"},
		Permissions: join(readCore, []Permission{
			PentestRead, PentestCampaignsRead, PentestFindingsRead,
			CompensatingControlsRead, CompensatingControlsWrite,
			AttackerProfilesRead, ThreatIntelRead, FindingsComment,
			CTEMCyclesRead, VerificationChecklistsRead, ReportsRead,
		}),
	},
	{
		ID:      "external-tester",
		Version: 1,
		Name:    "External tester",
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
		ID:      "researcher",
		Version: 2,
		Name:    "Researcher",
		Description: "Tests the bug-bounty programs the organization follows: programs, scans and " +
			"findings of the programs whose team they belong to. Reports and discusses findings; " +
			"cannot re-score severity, change the organization's own scope or approve anything.",
		Personas: []string{"Bug-bounty researcher", "Independent security researcher"},
		// The grants of the former built-in Researcher role (RFC-065 §7).
		Permissions: []Permission{
			DashboardRead, AssetsRead,
			FindingsRead, FindingsWrite, FindingsComment, FindingsStatus, FindingsTriage, FindingsExport,
			ScansRead, ScansWrite, ScansExecute,
			ScanProfilesRead, ScannerTemplatesRead, ScanWorkflowsRead,
			ProgramsRead, ProgramsWrite,
		},
	},
	{
		ID:      "bounty-triager",
		Version: 1,
		Name:    "Bug-bounty triager",
		Description: "Triages what researchers report: validates, de-duplicates, sets severity and " +
			"status, assigns and comments. Never approves risk acceptance or suppressions and never " +
			"changes program scope.",
		Personas: []string{"Bug-bounty program triager", "Vulnerability disclosure coordinator"},
		Permissions: join(readCore, []Permission{
			FindingsWrite, FindingsComment, FindingsSeverity, FindingsTriage, FindingsStatus, FindingsAssign,
			ProgramsRead, ScopeRead, SuppressionsRead,
		}),
	},
	{
		ID:      "threat-intel-analyst",
		Version: 1,
		Name:    "Threat intelligence analyst",
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
		ID:      "risk-approver",
		Version: 2,
		Name:    "Risk approver",
		Description: "Governance: approves or rejects risk acceptance, false positives and suppression " +
			"rules, and maintains compliance assessments. Holds no fix or triage permission, so the " +
			"person who asks is never the person who approves.",
		Personas: []string{"GRC and risk manager", "Compliance manager"},
		Permissions: join(readCore, []Permission{
			FindingsApprove, FindingsComment, SuppressionsRead, SuppressionsApprove,
			// With findings:approve: accept or dismiss an exposure. Alone it
			// changes nothing (resolve and severity need other writes).
			ExposuresTriage,
			ComplianceFrameworksRead, ComplianceAssessmentsRead, ComplianceAssessmentsWrite,
			ComplianceMappingsRead, ComplianceMappingsWrite,
			SLARead, CTEMCyclesRead, BusinessServicesRead, CompensatingControlsRead, ReportsRead, ReportsWrite,
		}),
	},
	{
		ID:      "auditor",
		Version: 2,
		Name:    "Auditor",
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
			PentestRead, PentestCampaignsRead, PentestFindingsRead, PentestRetestsRead,
			AutomationsRead, RolesRead, GroupsRead, ReportsRead,
		}),
	},
	{
		ID:      "executive",
		Version: 1,
		Name:    "Executive viewer",
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
