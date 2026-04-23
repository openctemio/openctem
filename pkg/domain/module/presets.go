package module

// Module presets — curated module bundles that admins apply instead of
// toggling ~100 modules one by one. Static Go spec (like
// ModuleDependencies) so presets evolve with product via code commits;
// tenants materialise the choice into `tenant_modules` when they apply.
//
// Design invariants (enforced by presets_test.go):
//
//   1. Every module ID in EnabledModules exists in the catalogue
//      (ModulePermissionMapping ∪ CoreModuleIDs).
//   2. Every hard dep of an enabled module is also enabled.
//      (Transitively — via TransitiveDependencies.)
//   3. Every core module is implicitly enabled (admins cannot opt out).
//   4. Preset IDs are unique.
//
// Adding a preset: append to ModulePresets, add a row to the UI preset
// picker, run tests. No migration needed — tenants pull fresh from Go.

// ModulePreset defines a curated bundle of enabled modules for a
// specific use case (e.g. "VM Essentials" for SMB vulnerability teams).
type ModulePreset struct {
	// ID — stable identifier, used by the apply endpoint. kebab-case.
	ID string
	// Name — display label shown to admins.
	Name string
	// Description — one-sentence summary of the bundle's purpose.
	Description string
	// TargetPersona — who this preset is designed for.
	TargetPersona string
	// KeyOutcomes — 3-5 bullets the admin can expect after applying.
	KeyOutcomes []string
	// EnabledModules — explicit allow-list. Core modules may be
	// omitted; they get implicitly included. Hard deps must all be
	// present — enforced by TestPresetsSatisfyHardDeps at CI.
	EnabledModules []string
	// Icon — lucide icon name for the preset card.
	Icon string
	// RecommendedFor — audience tags (e.g. "SMB", "mid-market",
	// "security analyst"). Used in marketing copy on the picker.
	RecommendedFor []string
}

// ModulePresets is the static catalogue of bundles shown on the
// Settings → Modules preset picker and during tenant onboarding.
// Order matters — presented to users in this order in the UI.
var ModulePresets = []ModulePreset{
	presetMinimal,
	presetAssetInventory,
	presetVMEssentials,
	presetASM,
	presetOffensive, // Merged Bug Bounty + Pentest/Red Team
	presetSBOM,
	presetCSPM,
	presetCompliance,
	presetCTEMFull,
}

// DefaultPresetID is the preset applied when a tenant is created
// without an explicit choice. "ctem_full" keeps the prior behaviour
// (all modules on) so existing flows don't regress.
const DefaultPresetID = "ctem_full"

// MandatoryModuleIDs lists modules every preset must include —
// "operational essentials" that any persona needs regardless of their
// security workflow choice. Distinct from CoreModuleIDs (which the
// platform forbids disabling at all): mandatory modules CAN be
// disabled by an admin post-apply if they really know what they're
// doing, but presets always opt them in by default.
//
// Why each one (cross-checked against the actual ingestion pipeline,
// not just the module name):
//
//   - agents → DATA INGESTION GATEWAY. Every collector / scanner /
//     SBOM tool POSTs data through /api/v1/agent/ingest, authenticated
//     by an agent API key. Without `agents` enabled, the tenant cannot
//     register collectors, cannot receive scanner output, cannot
//     ingest cloud asset data via push collectors. Architecturally
//     this is more important than most "feature" modules because
//     disabling it severs the tenant from any external data source
//     that uses the modern push model.
//
//   - notification_settings → every org needs alert routing config UI
//
//   - integrations → parent module the Integrations page hangs off;
//     also gates the pull-model code path (GitHub, AWS, GCP API
//     polling) used when collectors aren't deployed
//
//   - integrations.notifications → Slack/Teams/Email channel
//     registration — every org needs at least one alert channel
//
//   - groups → RBAC team scoping for any non-trivial permission grant
//
//   - api_keys → programmatic access (CI/CD pipelines, scripts,
//     out-of-band agent registration)
//
// Auto-included by ResolvePresetModules so individual presets don't
// have to enumerate them. Adding a module here = retroactive opt-in
// for every tenant on next preset apply.
var MandatoryModuleIDs = map[string]bool{
	"agents":                     true,
	"notification_settings":      true,
	"integrations":               true,
	"integrations.notifications": true,
	"groups":                     true,
	"api_keys":                   true,
}

// FindPreset returns the preset with the given ID, or nil when not found.
func FindPreset(id string) *ModulePreset {
	for i := range ModulePresets {
		if ModulePresets[i].ID == id {
			return &ModulePresets[i]
		}
	}
	return nil
}

// ResolvePresetModules returns the full set of module IDs a preset
// enables, including:
//   - every module in EnabledModules
//   - every core module (auto-on)
//   - every hard transitive dep of the above (auto-on to satisfy graph)
//
// The returned set is what should be written to tenant_modules when the
// preset is applied. Modules not in the set are treated as disabled.
func ResolvePresetModules(p *ModulePreset) map[string]bool {
	enabled := make(map[string]bool,
		len(p.EnabledModules)+len(CoreModuleIDs)+len(MandatoryModuleIDs))

	// Core always on (platform requirement).
	for id := range CoreModuleIDs {
		enabled[id] = true
	}
	// Mandatory always on for every preset (operational essentials).
	for id := range MandatoryModuleIDs {
		enabled[id] = true
	}
	// Explicit allow-list from the preset.
	for _, id := range p.EnabledModules {
		enabled[id] = true
	}
	// Pull hard transitive deps of each enabled module.
	for id := range enabled {
		for _, dep := range TransitiveDependencies(id) {
			enabled[dep] = true
		}
	}
	return enabled
}

// =============================================================================
// PRESET DEFINITIONS
// =============================================================================
//
// Kept as unexported vars in this file so the catalogue (ModulePresets)
// can be re-ordered / extended without having to scroll through body
// definitions. Each one is documented with its target persona and the
// reasoning behind in/out decisions.
// =============================================================================

// presetMinimal — only core modules. Used for staging/dev sandboxes or
// when an admin wants to start from a blank slate and opt modules in
// one by one.
var presetMinimal = ModulePreset{
	ID:            "minimal",
	Name:          "Minimal",
	Description:   "Only essential platform modules. Start blank and opt-in features one by one.",
	TargetPersona: "Sandbox / dev environment / feature evaluation",
	Icon:          "Package",
	RecommendedFor: []string{
		"sandbox",
		"demo",
		"dev",
	},
	KeyOutcomes: []string{
		"Only the 8 core modules are enabled (dashboard, assets, findings, scans, team, roles, audit, settings)",
		"All optional features stay off until you opt in",
		"Useful for minimal-noise demos or when evaluating specific modules in isolation",
	},
	// Empty — core modules are auto-included by ResolvePresetModules.
	EnabledModules: []string{},
}

// presetAssetInventory — IT asset inventory / CMDB-style use case.
// Some orgs just want a central asset register (ownership, services,
// relationships, cloud accounts) without security workflow noise.
// `assets` is core so it's always on; sub-module inheritance enables
// every assets.* type automatically. Findings/scans remain core too
// (platform requires them) but every security-analysis feature is off
// — the Findings page will exist but be empty.
var presetAssetInventory = ModulePreset{
	ID:            "asset_inventory",
	Name:          "Asset Inventory",
	Description:   "IT asset register: inventory, ownership, business-services mapping, relationships. No security workflow.",
	TargetPersona: "IT asset manager / platform ops / CMDB team",
	Icon:          "Database",
	RecommendedFor: []string{
		"IT asset management",
		"CMDB replacement",
		"platform ops",
		"pre-security rollout",
	},
	KeyOutcomes: []string{
		"Central asset register across on-prem, cloud, SaaS (every asset type enabled)",
		"Business-service mapping for criticality context",
		"Asset relationships for dependency visualization",
		"Attack surface view + ownership — no CVE/finding workflow yet",
	},
	EnabledModules: []string{
		// Scoping — map assets to business context
		"attack_surface", "scope_config", "business_services", "relationships",
		// Discovery
		"components", "branches",
		// Insights — asset-level reporting only
		"reports",
		// Settings — cloud + SCM for asset ingestion
		"integrations", "integrations.cloud", "integrations.scm",
		"integrations.notifications",
	},
}

// presetVMEssentials — traditional vulnerability management for SMB /
// mid-market teams that just want "know assets → scan → CVE → fix →
// report". Includes asset visibility (you can't manage vulns of
// unknown assets) but skips CTEM-maturity / pentest / attack
// simulation — those require dedicated team capacity beyond routine VM.
var presetVMEssentials = ModulePreset{
	ID:            "vm_essentials",
	Name:          "Vulnerability Management Essentials",
	Description:   "Asset-aware vuln workflow: discover → scan → triage → remediate → report. Replaces traditional VM tools.",
	TargetPersona: "Security analyst at SMB/mid-market — replacing Tenable/Qualys",
	Icon:          "ShieldAlert",
	RecommendedFor: []string{
		"SMB",
		"mid-market",
		"security analyst",
		"replacing legacy VM tools",
	},
	KeyOutcomes: []string{
		"Asset inventory (every type) + attack surface view",
		"Automated CVE scanning with KEV/EPSS enrichment",
		"AI-assisted triage and bulk actions",
		"SLA tracking, remediation tasks, suppressions, workflows",
		"Executive-ready reports + SBOM export",
	},
	EnabledModules: []string{
		// Scoping — even a basic VM team needs an asset surface view
		// to know "what's in scope this scan cycle". Skip business
		// services + attacker profiles (those are CTEM-level concerns).
		"attack_surface", "scope_config", "relationships",
		// Discovery
		"components", "branches", "credentials",
		// Prioritization
		"threat_intel", "ai_triage", "ai_triage.auto", "ai_triage.bulk",
		"priority_rules", "risk_scoring", "risk_analysis", "sla",
		// Mobilization
		"remediation", "remediation_tasks", "suppressions", "workflows", "policies",
		// Insights
		"reports", "executive_summary", "sbom_export",
		// Settings / ops
		"integrations", "integrations.scm", "integrations.scanners",
		"integrations.notifications", "integrations.ticketing",
		"scanner_templates", "scan_profiles", "tools", "scan_pipelines",
		"iocs",
	},
}

// presetASM — Attack Surface Management for OWN-org external recon.
// Continuous monitoring of internet-facing assets, exposure surfacing,
// shadow-IT discovery. Light on remediation (handed off elsewhere).
var presetASM = ModulePreset{
	ID:            "asm",
	Name:          "Attack Surface Management",
	Description:   "Continuous discovery of own-org external-facing assets, exposure tracking, shadow IT detection.",
	TargetPersona: "External recon / ASM team / pre-pentest scoping",
	Icon:          "Globe",
	RecommendedFor: []string{
		"external recon",
		"ASM team",
		"pre-pentest scoping",
		"shadow IT discovery",
	},
	KeyOutcomes: []string{
		"All asset types tracked (domains, subdomains, IPs, certs, web apps, cloud)",
		"Exposure surfacing with KEV/EPSS context",
		"Attack path modelling via asset relationships and attacker profiles",
		"Auto-alert workflows on new exposed asset detection",
		"Executive-level attack surface dashboard",
	},
	EnabledModules: []string{
		// Scoping (full — ASM is all about scoping)
		"attack_surface", "scope_config", "business_services",
		"relationships", "attacker_profiles",
		// Discovery
		"components", "credentials",
		// Prioritization
		"threat_intel", "ai_triage", "risk_analysis", "risk_scoring",
		"priority_rules",
		// Mobilization — workflow alert on new exposure
		"workflows", "suppressions",
		// Insights
		"reports", "executive_summary", "mitre_coverage",
		// Settings + ops
		"integrations", "integrations.cloud", "integrations.scm",
		"integrations.scanners", "integrations.notifications",
		"scanner_templates", "scan_profiles", "tools", "scan_pipelines",
	},
}

// presetOffensive — unified preset for offensive security work:
// bug bounty hunters, pentest consultancies, internal red teams.
//
// Why merged: bug bounty and pentest share ~85% of their module
// surface (recon, finding lifecycle, AI triage, MITRE mapping,
// attacker profiles, report generation, CTEM cycles per engagement).
// The differences (BAS / control_testing for red team; webhook
// submission for bug bounty) are tweakable post-apply rather than
// justifying two near-duplicate presets.
//
// Persona examples:
//   - Solo bug bounty hunter on HackerOne/Bugcrowd
//   - Pentest consultancy doing client engagements
//   - Internal red team running adversary emulation
//   - Freelancer doing both pentest and bounty
var presetOffensive = ModulePreset{
	ID:            "offensive",
	Name:          "Offensive Security",
	Description:   "Pentest, red team, bug bounty — recon, vulnerability discovery, MITRE mapping, professional reports.",
	TargetPersona: "Pentester / red team / bug bounty hunter — anyone on the offensive side",
	Icon:          "Crosshair",
	RecommendedFor: []string{
		"pentest consultancy",
		"internal red team",
		"bug bounty hunter",
		"security researcher",
		"adversary emulation",
		"multi-target operator",
	},
	KeyOutcomes: []string{
		"Per-target / per-engagement scope (CTEM cycle each) with full asset visibility",
		"Heavy recon: subdomains, IPs, services, components, cloud — every asset type",
		"AI-assisted triage to prioritize WHAT to dig into next",
		"MITRE ATT&CK coverage heatmap per engagement",
		"BAS + control testing for red team validation (toggle off for pure bounty)",
		"Professional reports + executive summaries; webhook submissions for bounty platforms",
	},
	EnabledModules: []string{
		// Scoping (full — every offensive engagement needs scope)
		"attack_surface", "scope_config", "business_services",
		"ctem_cycles", "attacker_profiles", "relationships",
		// Discovery — recon-heavy
		"components", "branches", "credentials",
		// Validation — keep on for red team; bounty hunters can
		// disable BAS / control_testing post-apply if not needed
		"pentest", "attack_simulation", "control_testing",
		"compensating_controls",
		// Prioritization
		"threat_intel", "ai_triage", "ai_triage.auto", "ai_triage.bulk",
		"ai_triage.custom_prompts", "ai_triage.workflow",
		"priority_rules", "risk_scoring", "risk_analysis", "sla",
		// Mobilization — handoff (pentest) + auto-submit (bounty)
		"workflows", "suppressions", "remediation",
		// Insights — reports are the deliverable for both
		"reports", "executive_summary", "mitre_coverage", "ctem_maturity",
		// Operations — recon scanning at scale
		"scanner_templates", "template_sources", "scan_pipelines",
		"scan_profiles", "tools", "iocs",
		// Settings — webhook (bounty) + ticketing (pentest handoff)
		"integrations", "integrations.scm", "integrations.cloud",
		"integrations.scanners", "integrations.webhooks",
		"integrations.ticketing", "integrations.notifications",
	},
}

// presetSBOM — DevSecOps / AppSec focused on software composition.
// Component-heavy, SCM-heavy, CI/CD pipeline gating. Asset surface
// scoped to repos + containers + artifacts (assets is core, all
// asset types inherit). Skips pentest and compliance.
var presetSBOM = ModulePreset{
	ID:            "sbom_supply_chain",
	Name:          "SBOM & Supply Chain Security",
	Description:   "Asset-aware software composition analysis, license compliance and dependency vulnerability management.",
	TargetPersona: "AppSec engineer / DevSecOps",
	Icon:          "Package",
	RecommendedFor: []string{
		"AppSec team",
		"DevSecOps",
		"supply chain security",
		"CI/CD gating",
	},
	KeyOutcomes: []string{
		"Asset map: repos → branches → components → containers/artifacts",
		"SBOM generation (SPDX/CycloneDX) per repository and build",
		"Transitive dependency CVE tracking with KEV/EPSS",
		"License risk visibility across components",
		"CI/CD pipeline policy gates with workflow automation",
	},
	EnabledModules: []string{
		// Scoping — repos belong to apps/services, need that map
		"attack_surface", "scope_config", "business_services", "relationships",
		// Discovery — component-heavy
		"components", "branches", "credentials",
		// Prioritization
		"threat_intel", "ai_triage", "ai_triage.auto", "ai_triage.bulk",
		"priority_rules", "risk_scoring", "risk_analysis", "sla",
		// Mobilization
		"remediation", "remediation_tasks", "suppressions", "workflows",
		"policies",
		// Insights — SBOM is the key deliverable
		"sbom_export", "reports", "executive_summary",
		// Settings — SCM/CI integration heavy
		"integrations", "integrations.scm", "integrations.pipelines",
		"integrations.scanners", "integrations.notifications",
		"integrations.ticketing",
		"scanner_templates", "template_sources", "scan_pipelines",
		"tools", "scan_profiles",
	},
}

// presetCSPM — Cloud Security Posture Management for cloud-native orgs.
// Distinct from VM (which covers on-prem/host scanning). Focuses on
// cloud misconfig, IaC and container/k8s/serverless workloads.
var presetCSPM = ModulePreset{
	ID:            "cspm",
	Name:          "Cloud Security Posture",
	Description:   "Cloud-native security: misconfig detection, IaC scanning, container and k8s posture.",
	TargetPersona: "Cloud security engineer / platform team",
	Icon:          "Cloud",
	RecommendedFor: []string{
		"cloud-native",
		"platform team",
		"multi-cloud",
		"Kubernetes operators",
	},
	KeyOutcomes: []string{
		"Continuous cloud account scanning (AWS, GCP, Azure)",
		"Container and Kubernetes workload posture",
		"IaC security via SCM/CI integration",
		"Compliance mapping to CIS / NIST benchmarks",
	},
	EnabledModules: []string{
		// Scoping
		"attack_surface", "scope_config", "business_services", "relationships",
		// Discovery — cloud-native asset types
		"components", "credentials",
		// Prioritization
		"threat_intel", "ai_triage", "priority_rules",
		"risk_analysis", "risk_scoring", "sla",
		// Validation
		"compensating_controls", "control_testing",
		// Mobilization
		"remediation", "remediation_tasks", "suppressions", "workflows", "policies",
		// Insights
		"reports", "executive_summary", "mitre_coverage", "ctem_maturity",
		// Settings — cloud integrations heavy
		"integrations", "integrations.cloud", "integrations.scm",
		"integrations.pipelines", "integrations.scanners",
		"integrations.notifications", "integrations.siem",
		"scanner_templates", "template_sources", "scan_pipelines",
		"tools", "scan_profiles", "iocs",
		// Compliance (light — for cloud benchmarks)
		"compliance",
	},
}

// presetCompliance — GRC / audit-focused. Framework mapping, control
// tracking, evidence collection. Needs asset-to-control mapping
// (compliance frameworks audit specific assets/services). Skips
// offensive modules — auditors don't pentest.
var presetCompliance = ModulePreset{
	ID:            "compliance",
	Name:          "Compliance & Audit",
	Description:   "Framework-driven compliance — PCI, SOC2, ISO 27001, HIPAA — with asset-to-control mapping and evidence tracking.",
	TargetPersona: "GRC / compliance officer / auditor",
	Icon:          "ClipboardCheck",
	RecommendedFor: []string{
		"GRC team",
		"compliance officer",
		"audit preparation",
		"framework mapping",
	},
	KeyOutcomes: []string{
		"Asset-to-control mapping (which controls audit which assets/services)",
		"Map findings and controls to PCI/SOC2/ISO/HIPAA frameworks",
		"Compensating control tracking for residual risk",
		"Quarterly audit-ready reports + executive summary",
		"CTEM maturity scoring for board reporting",
	},
	EnabledModules: []string{
		// Scoping — controls audit specific assets
		"attack_surface", "scope_config", "business_services",
		// Compliance
		"compliance", "policies",
		// Validation
		"compensating_controls", "control_testing",
		// Discovery — light, just enough for asset mapping
		"components",
		// Prioritization
		"threat_intel", "priority_rules", "risk_analysis", "risk_scoring", "sla",
		// Mobilization
		"remediation", "remediation_tasks", "suppressions", "workflows",
		// Insights (heavy)
		"reports", "executive_summary", "ctem_maturity", "mitre_coverage",
		// Settings
		"integrations", "integrations.ticketing", "integrations.notifications",
	},
}

// presetCTEMFull — Gartner CTEM full lifecycle for mature orgs.
// Almost everything on except bug-bounty-specific and commercial-only
// modules that don't make sense for OSS.
var presetCTEMFull = ModulePreset{
	ID:            "ctem_full",
	Name:          "CTEM Full Lifecycle",
	Description:   "Gartner CTEM — all 5 phases: scoping, discovery, prioritization, validation, mobilization.",
	TargetPersona: "Mature security org implementing CTEM",
	Icon:          "Layers",
	RecommendedFor: []string{
		"enterprise",
		"mature security org",
		"Gartner CTEM adopter",
		"CSO-led programme",
	},
	KeyOutcomes: []string{
		"All 5 CTEM phases fully operational",
		"Quarterly CTEM cycles with maturity scoring",
		"Full attack surface ↔ business impact mapping",
		"Cross-phase executive dashboard",
	},
	EnabledModules: []string{
		// Scoping
		"attack_surface", "scope_config", "business_services",
		"ctem_cycles", "attacker_profiles", "relationships",
		// Discovery
		"components", "branches", "credentials",
		// Prioritization
		"threat_intel", "ai_triage", "ai_triage.auto", "ai_triage.bulk",
		"ai_triage.workflow", "ai_triage.custom_prompts",
		"priority_rules", "risk_analysis", "business_impact",
		"risk_scoring", "sla",
		// Validation
		"pentest", "attack_simulation", "control_testing",
		"compensating_controls",
		// Mobilization
		"remediation", "remediation_tasks", "workflows",
		"suppressions", "policies",
		// Insights
		"reports", "executive_summary", "ctem_maturity",
		"mitre_coverage", "sbom_export",
		// Operations
		"scanner_templates", "template_sources", "scan_pipelines",
		"scan_profiles", "tools", "iocs",
		// Compliance
		"compliance",
		// Integrations — all
		"integrations", "integrations.scm", "integrations.cloud",
		"integrations.ticketing", "integrations.notifications",
		"integrations.siem", "integrations.scanners",
		"integrations.pipelines", "integrations.webhooks",
		"integrations.api",
	},
}
