package authzdoc

// Persona is one kind of person (or machine) that uses OpenCTEM, with the
// recommended way to give it access: roles for what it may do, a team for
// what it may see, and how long the access lasts.
type Persona struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"` // persona group for display
	Goal  string `json:"goal"`
	// Stages of the CTEM cycle the persona works in.
	Stages []string `json:"stages,omitempty"`
	// Roles: system role slugs and role template ids, combined.
	Roles []string `json:"roles"`
	// Team is the recommended team (access group) pattern id, if any.
	Team string `json:"team,omitempty"`
	// DataScope says what the persona should see.
	DataScope string `json:"data_scope"`
	// Access says how the access is granted and when it ends.
	Access string `json:"access"`
	// MustNot lists what the persona must not be able to do.
	MustNot []string `json:"must_not,omitempty"`
}

// TeamPattern is a recommended team (access group): who is in it, which
// assets it holds and which roles its members usually carry.
type TeamPattern struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	GroupType string   `json:"group_type"` // groups.group_type
	Purpose   string   `json:"purpose"`
	Assets    string   `json:"assets"` // how the team's data scope is defined
	Roles     []string `json:"roles"`
	Expiring  bool     `json:"expiring,omitempty"` // memberships should carry an end date
}

// TeamPatterns, in display order.
var TeamPatterns = []TeamPattern{
	{
		ID: "security-operations", Name: "Security operations", GroupType: "security_team",
		Purpose: "The central security team that triages and validates across the program scope.",
		Assets:  "A scope rule on the asset groups (or tags) that make up the current CTEM scope.",
		Roles:   []string{"security-analyst", "vulnerability-manager", "threat-intel-analyst"},
	},
	{
		ID: "business-unit", Name: "Business unit: <name>", GroupType: "department",
		Purpose: "Everyone who owns or fixes the systems of one business unit, and its leader.",
		Assets:  "A scope rule on the business unit's tag (for example bu:payments) or its asset groups.",
		Roles:   []string{"remediation-owner", "executive"},
	},
	{
		ID: "product-team", Name: "Product: <name>", GroupType: "team",
		Purpose: "A product's engineers: its repositories, services and hosts.",
		Assets:  "The product's asset group, or a scope rule on its tag; repositories by owner.",
		Roles:   []string{"remediation-owner", "appsec-engineer"},
	},
	{
		ID: "platform-infrastructure", Name: "Infrastructure: <domain>", GroupType: "team",
		Purpose: "IT and infrastructure engineers for one domain (network, cloud account, endpoints).",
		Assets:  "A scope rule on the domain's tag or asset group (for example env:cloud-prod).",
		Roles:   []string{"remediation-owner", "scan-operator"},
	},
	{
		ID: "validation", Name: "Validation and red team", GroupType: "security_team",
		Purpose: "Internal testers who prove exploitability on the prioritized exposures.",
		Assets:  "The assets in the current validation scope (an asset group refreshed each cycle).",
		Roles:   []string{"validation-engineer"},
	},
	{
		ID: "engagement", Name: "Engagement: <vendor> <dates>", GroupType: "external",
		Purpose:  "One external testing engagement. Pair with a pentest campaign whose team is this group.",
		Assets:   "Only the assets named in the rules of engagement, added explicitly.",
		Roles:    []string{"external-tester"},
		Expiring: true,
	},
	{
		ID: "bounty-program", Name: "Program: <bug-bounty program>", GroupType: "project",
		Purpose: "Researchers working one bug-bounty program (RFC-064).",
		Assets:  "The program's targets; nothing from the organization's own inventory.",
		Roles:   []string{"researcher"},
	},
	{
		ID: "leadership", Name: "Leadership", GroupType: "department",
		Purpose: "Executives who follow outcomes on dashboards and reports.",
		Assets:  "A scope rule on the crown-jewel and in-scope asset groups, or per business unit.",
		Roles:   []string{"executive"},
	},
	{
		ID: "audit", Name: "Audit <period>", GroupType: "external",
		Purpose:  "Auditors for one audit period. The auditor role sees all data, so the team only tracks membership and its end date.",
		Assets:   "None needed (the auditor role carries full data access).",
		Roles:    []string{"auditor"},
		Expiring: true,
	},
}

// Personas, in display order.
var Personas = []Persona{
	// Organization administration.
	{
		ID: "org-owner", Name: "Organization owner", Group: "Administration",
		Goal:      "Accountable for the organization in OpenCTEM: billing, administrators, deletion.",
		Roles:     []string{"owner"},
		DataScope: "Everything (built in).",
		Access:    "One named owner plus a backup administrator. Not the account used for daily work.",
		MustNot:   []string{"share the account", "use it without two-factor authentication"},
	},
	{
		ID: "org-admin", Name: "Organization administrator", Group: "Administration",
		Goal:      "Runs the tool: members, teams, roles, SSO, integrations, sensors.",
		Roles:     []string{"admin"},
		DataScope: "Everything (built in).",
		Access:    "Granted only by the owner, with step-up. Keep to two or three people.",
		MustNot:   []string{"manage other administrators (owner only)", "delete the organization"},
	},
	// Security program.
	{
		ID: "ciso", Name: "CISO or security leader", Group: "Security program",
		Goal:      "Sets risk appetite, sponsors the program, approves material risk acceptance, reports to the board.",
		Stages:    []string{StageScoping, StagePrioritization, StageMobilization},
		Roles:     []string{"program-lead"},
		DataScope: "Everything (the template carries full data access).",
		Access:    "Permanent.",
		MustNot:   []string{"triage or fix findings they then approve", "administer members or sensors"},
	},
	{
		ID: "program-manager", Name: "CTEM program manager", Group: "Security program",
		Goal:      "Runs each cycle: scope charter, priority policy and SLAs, approvals, metrics.",
		Stages:    []string{StageScoping, StagePrioritization, StageValidation, StageMobilization},
		Roles:     []string{"program-lead"},
		DataScope: "Everything.",
		Access:    "Permanent.",
		MustNot:   []string{"widen scope and approve the same change", "approve their own risk requests"},
	},
	{
		ID: "security-analyst", Name: "Security analyst", Group: "Security program",
		Goal:      "Triages findings and exposures, assigns owners, verifies fixes.",
		Stages:    []string{StageDiscovery, StagePrioritization, StageMobilization},
		Roles:     []string{"security-analyst"},
		Team:      "security-operations",
		DataScope: "The program scope, through the security operations team.",
		Access:    "Permanent.",
		MustNot:   []string{"approve risk acceptance or false positives", "delete findings", "reveal secrets"},
	},
	{
		ID: "vulnerability-manager", Name: "Vulnerability manager", Group: "Security program",
		Goal:      "Owns the remediation backlog, routing rules, campaigns and SLA reporting.",
		Stages:    []string{StagePrioritization, StageMobilization},
		Roles:     []string{"vulnerability-manager"},
		Team:      "security-operations",
		DataScope: "The program scope.",
		Access:    "Permanent.",
		MustNot:   []string{"approve risk acceptance", "change scope"},
	},
	{
		ID: "threat-intel", Name: "Threat intelligence analyst", Group: "Security program",
		Goal:      "Keeps attacker profiles and threat intel current; records leaked credentials and lookalike domains.",
		Stages:    []string{StageDiscovery, StagePrioritization},
		Roles:     []string{"threat-intel-analyst"},
		Team:      "security-operations",
		DataScope: "The program scope; external exposures.",
		Access:    "Permanent.",
		MustNot:   []string{"reveal leaked secrets (owner and administrators, with step-up)"},
	},
	{
		ID: "brand-protection", Name: "Brand protection or legal", Group: "Security program",
		Goal:      "Acts on lookalike domains and brand impersonation (takedowns).",
		Stages:    []string{StageDiscovery, StageMobilization},
		Roles:     []string{"threat-intel-analyst"},
		Team:      "security-operations",
		DataScope: "Domain assets and their exposures.",
		Access:    "Permanent.",
		MustNot:   []string{"run scans", "see unrelated findings"},
	},
	{
		ID: "appsec", Name: "AppSec or DevSecOps engineer", Group: "Security program",
		Goal:      "Runs code, dependency and secret scanning for repositories; works the CI gate with developers.",
		Stages:    []string{StageDiscovery, StageMobilization},
		Roles:     []string{"appsec-engineer"},
		Team:      "product-team",
		DataScope: "The repositories and services of the products they cover.",
		Access:    "Permanent.",
		MustNot:   []string{"override the CI gate (administrators)", "author scanner templates (administrators)"},
	},
	{
		ID: "cloud-security", Name: "Cloud security engineer", Group: "Security program",
		Goal:      "Triages cloud exposures and runs scans of cloud accounts.",
		Stages:    []string{StageDiscovery, StagePrioritization},
		Roles:     []string{"security-analyst", "scan-operator"},
		Team:      "platform-infrastructure",
		DataScope: "The cloud accounts and their resources.",
		Access:    "Permanent.",
		MustNot:   []string{"manage sensors or scan zones (administrators)"},
	},
	{
		ID: "red-team", Name: "Red team or internal penetration tester", Group: "Security program",
		Goal:      "Proves exploitability and attack paths on prioritized exposures.",
		Stages:    []string{StageValidation},
		Roles:     []string{"validation-engineer"},
		Team:      "validation",
		DataScope: "The current validation scope.",
		Access:    "Permanent; campaign membership per engagement.",
		MustNot:   []string{"test outside approved scope", "approve risk"},
	},
	{
		ID: "bas-engineer", Name: "Breach and attack simulation engineer", Group: "Security program",
		Goal:      "Runs simulations and control tests; checks that detections fire.",
		Stages:    []string{StageValidation},
		Roles:     []string{"validation-engineer"},
		Team:      "validation",
		DataScope: "The assets the simulations target.",
		Access:    "Permanent.",
		MustNot:   []string{"run simulations against assets outside their act scope"},
	},
	{
		ID: "detection-engineer", Name: "Detection engineer or SOC analyst", Group: "Security program",
		Goal:      "Uses validation results to tune detections; follows exposures on critical assets.",
		Stages:    []string{StageValidation, StageMobilization},
		Roles:     []string{"security-analyst"},
		Team:      "security-operations",
		DataScope: "The program scope.",
		Access:    "Permanent.",
		MustNot:   []string{"approve risk"},
	},
	{
		ID: "scan-operator", Name: "Scanning operations engineer", Group: "Security program",
		Goal:      "Schedules and runs scans and workflows on approved scope.",
		Stages:    []string{StageDiscovery},
		Roles:     []string{"scan-operator"},
		Team:      "platform-infrastructure",
		DataScope: "The assets they scan.",
		Access:    "Permanent.",
		MustNot:   []string{"change scope", "manage sensors", "change findings"},
	},
	// Owners and fixers.
	{
		ID: "asset-owner", Name: "Asset or system owner", Group: "Owners and fixers",
		Goal:      "Accountable for their systems: fixes or requests risk acceptance with a reason.",
		Stages:    []string{StageMobilization},
		Roles:     []string{"remediation-owner"},
		Team:      "business-unit",
		DataScope: "Their business unit's or system's assets only.",
		Access:    "Permanent; usually provisioned by SCIM into the team.",
		MustNot:   []string{"verify their own fix", "approve their own risk request", "see other units' findings"},
	},
	{
		ID: "it-ops", Name: "IT or infrastructure engineer", Group: "Owners and fixers",
		Goal:      "Patches and reconfigures hosts, network devices and cloud resources.",
		Stages:    []string{StageMobilization},
		Roles:     []string{"remediation-owner"},
		Team:      "platform-infrastructure",
		DataScope: "Their infrastructure domain.",
		Access:    "Permanent.",
		MustNot:   []string{"verify their own fix", "change scans or scope"},
	},
	{
		ID: "developer", Name: "Developer", Group: "Owners and fixers",
		Goal:      "Fixes code and dependency findings in their repositories.",
		Stages:    []string{StageMobilization},
		Roles:     []string{"remediation-owner"},
		Team:      "product-team",
		DataScope: "Their product's repositories and services.",
		Access:    "Permanent; usually through SSO and SCIM.",
		MustNot:   []string{"verify their own fix", "see other products' findings"},
	},
	{
		ID: "engineering-manager", Name: "Engineering manager", Group: "Owners and fixers",
		Goal:      "Plans remediation work for a team and follows its SLA.",
		Stages:    []string{StageMobilization},
		Roles:     []string{"remediation-owner", "executive"},
		Team:      "product-team",
		DataScope: "Their product's assets.",
		Access:    "Permanent.",
		MustNot:   []string{"approve risk acceptance"},
	},
	// Governance and leadership.
	{
		ID: "grc", Name: "GRC, risk or compliance manager", Group: "Governance and leadership",
		Goal:      "Approves time-bound risk acceptance and suppressions; maps controls to frameworks.",
		Stages:    []string{StagePrioritization, StageMobilization},
		Roles:     []string{"risk-approver"},
		Team:      "leadership",
		DataScope: "The assets whose risk they govern (or the whole scope).",
		Access:    "Permanent.",
		MustNot:   []string{"triage, fix or verify the findings they approve"},
	},
	{
		ID: "auditor", Name: "Internal or external auditor", Group: "Governance and leadership",
		Goal:      "Collects evidence: decisions, approvals, the audit log, exports.",
		Roles:     []string{"auditor"},
		Team:      "audit",
		DataScope: "Everything, read-only.",
		Access:    "External membership with an end date (90 days by default); internal auditors by the same team with an end date.",
		MustNot:   []string{"change anything", "keep access after the audit"},
	},
	{
		ID: "executive", Name: "Executive or board member", Group: "Governance and leadership",
		Goal:      "Follows outcomes: exposure trend, SLA performance, cycle results.",
		Roles:     []string{"executive"},
		Team:      "leadership",
		DataScope: "The crown-jewel and in-scope assets, or one business unit.",
		Access:    "Permanent.",
		MustNot:   []string{"see configuration, scans or member lists"},
	},
	{
		ID: "third-party-risk", Name: "Procurement or third-party risk", Group: "Governance and leadership",
		Goal:      "Follows exposures of vendor-managed systems and vendor credential dumps.",
		Roles:     []string{"executive"},
		Team:      "business-unit",
		DataScope: "Assets tagged as vendor-managed (a scope rule on a vendor tag).",
		Access:    "Permanent.",
		MustNot:   []string{"see internal findings unrelated to vendors"},
	},
	// External people.
	{
		ID: "pentest-vendor", Name: "External penetration testing vendor", Group: "External people",
		Goal:      "Tests within rules of engagement and reports findings into the campaign.",
		Stages:    []string{StageValidation},
		Roles:     []string{"external-tester"},
		Team:      "engagement",
		DataScope: "Only the engagement's assets and the campaign they are a member of.",
		Access:    "External membership (viewer on entry), mandatory end date when unmanaged; campaign role tester.",
		MustNot:   []string{"see the organization's other findings or inventory", "keep access after the engagement"},
	},
	{
		ID: "bounty-researcher", Name: "Bug-bounty researcher", Group: "External people",
		Goal:      "Hunts on bug-bounty programs and records findings against program targets.",
		Stages:    []string{StageDiscovery, StageValidation},
		Roles:     []string{"researcher"},
		Team:      "bounty-program",
		DataScope: "The targets of the programs they belong to.",
		Access:    "The built-in Researcher role (RFC-064) and a program group.",
		MustNot:   []string{"widen the organization's own scope", "approve scope entries"},
	},
	{
		ID: "mssp-analyst", Name: "Managed security service analyst", Group: "External people",
		Goal:      "Operates the program for a customer organization.",
		Stages:    []string{StageDiscovery, StagePrioritization, StageValidation, StageMobilization},
		Roles:     []string{"security-analyst"},
		Team:      "security-operations",
		DataScope: "The customer's program scope.",
		Access:    "An external membership in each customer organization (managed by the provider's own organization, which the customer trusts), never a cross-tenant account.",
		MustNot:   []string{"be an owner or administrator of the customer", "carry full data access", "reuse one customer's data in another"},
	},
	// Machines.
	{
		ID: "ci-pipeline", Name: "CI pipeline", Group: "Machines",
		Goal:      "Uploads scan results from a build and asks the gate for a verdict.",
		Stages:    []string{StageDiscovery, StageMobilization},
		Roles:     []string{},
		DataScope: "The repository the run is bound to.",
		Access:    "OIDC workload identity exchanged for a 15-minute run token (RFC-051); no user, no role, no API key.",
		MustNot:   []string{"read the organization's data", "override the gate"},
	},
	{
		ID: "api-integration", Name: "API integration", Group: "Machines",
		Goal:      "Reads data into another system (SIEM, data lake, ticketing).",
		Roles:     []string{},
		DataScope: "The teams the service account belongs to, never full data.",
		Access:    "A service account (no sign-in, never owner or administrator, no full data access) with a narrow custom role and its teams, acting through an oct_ API key minted for it; keys are read-only on the REST API and go with the account.",
		MustNot:   []string{"write through the REST API", "act as an administrator"},
	},
	{
		ID: "mcp-client", Name: "AI assistant (MCP client)", Group: "Machines",
		Goal:      "Answers questions about exposures for a signed-in person.",
		Roles:     []string{},
		DataScope: "The person's own data scope.",
		Access:    "An OAuth grant on the MCP endpoint (RFC-062): granted scopes intersected with the person's live permissions; the administrator bypass never applies.",
		MustNot:   []string{"exceed the person's permissions", "write without the person's confirmation"},
	},
	{
		ID: "platform-operator", Name: "Platform operator", Group: "Machines",
		Goal:      "Runs the OpenCTEM service: health, organizations, first owners.",
		Roles:     []string{},
		DataScope: "No organization data.",
		Access:    "The platform admin console realm (RFC-022), never a member of an organization.",
		MustNot:   []string{"read an organization's data without a support grant (RFC-063)"},
	},
}
