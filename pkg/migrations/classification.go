// Package migrations provides edition-aware database migration loading.
package migrations

// MigrationClassification maps migration numbers to their edition.
// This allows the existing flat migrations to be filtered by edition.
//
// Convention:
// - Migrations 000001-000049: Core (OSS)
// - Migrations 000050-000079: Enterprise
// - Migrations 000080-000099: SaaS Platform
// - Migrations 000100+: Features (tagged individually)
var MigrationClassification = map[string]Edition{
	// ========================================
	// Core Migrations (OSS) - 000001 to 000049
	// ========================================

	// Foundation
	"000001": EditionCore, // init_extensions
	"000002": EditionCore, // users_auth
	"000003": EditionCore, // tenants
	"000004": EditionCore, // assets
	"000005": EditionCore, // components
	"000006": EditionCore, // vulnerabilities
	"000007": EditionCore, // findings
	"000008": EditionCore, // exposures_attack_paths
	"000009": EditionCore, // scm_connections
	"000010": EditionCore, // asset_groups

	// Tools & Scanning
	"000011": EditionCore, // tools
	"000012": EditionCore, // capabilities
	"000013": EditionCore, // commands
	"000014": EditionCore, // agents
	"000015": EditionCore, // scans
	"000016": EditionCore, // scan_sessions
	"000017": EditionCore, // scopes
	"000018": EditionCore, // scan_profiles
	"000019": EditionCore, // scanner_templates
	"000020": EditionCore, // template_sources

	// Assets & Findings Extended
	"000021": EditionCore, // asset_components
	"000022": EditionCore, // branches
	"000023": EditionCore, // finding_sources
	"000024": EditionCore, // asset_identifiers
	"000025": EditionCore, // finding_activities
	"000026": EditionCore, // finding_comments
	"000027": EditionCore, // finding_suppression

	// Credentials & Secrets
	"000028": EditionCore, // credentials
	"000029": EditionCore, // secret_stores
	"000030": EditionCore, // credential_discovery

	// RBAC (Basic - OSS)
	"000031": EditionCore, // roles
	"000032": EditionCore, // permissions
	"000033": EditionCore, // role_permissions
	"000034": EditionCore, // user_roles
	"000035": EditionCore, // predefined_roles_seed

	// Indexes & Performance
	"000036": EditionCore, // indexes_findings
	"000037": EditionCore, // indexes_assets
	"000038": EditionCore, // indexes_scans
	"000039": EditionCore, // full_text_search

	// API Keys & Sessions
	"000040": EditionCore, // api_keys
	"000041": EditionCore, // sessions
	"000042": EditionCore, // refresh_tokens

	// Dashboard & Metrics
	"000043": EditionCore, // dashboard_metrics
	"000044": EditionCore, // asset_stats
	"000045": EditionCore, // finding_stats

	// Reserved Core (046-049)
	"000046": EditionCore,
	"000047": EditionCore,
	"000048": EditionCore,
	"000049": EditionCore,

	// ========================================
	// Enterprise Migrations - 000050 to 000079
	// ========================================

	// Advanced RBAC
	"000050": EditionEnterprise, // custom_roles
	"000051": EditionEnterprise, // permission_sets
	"000052": EditionEnterprise, // permission_set_items
	"000053": EditionEnterprise, // role_permission_sets

	// Audit & Compliance
	"000054": EditionEnterprise, // audit_logs
	"000055": EditionEnterprise, // audit_log_retention

	// SSO & Identity
	"000056": EditionEnterprise, // sso_configs
	"000057": EditionEnterprise, // oauth_providers
	"000058": EditionEnterprise, // saml_configs

	// SLA & Governance
	"000059": EditionEnterprise, // sla_policies
	"000060": EditionEnterprise, // sla_violations
	"000061": EditionEnterprise, // compliance_frameworks

	// Workflows & Automation
	"000062": EditionEnterprise, // workflows
	"000063": EditionEnterprise, // workflow_executions
	"000064": EditionEnterprise, // workflow_actions

	// Integrations
	"000065": EditionEnterprise, // integrations
	"000066": EditionEnterprise, // integration_events
	"000067": EditionEnterprise, // webhooks

	// Notifications
	"000068": EditionEnterprise, // notifications
	"000069": EditionEnterprise, // notification_configs
	"000070": EditionEnterprise, // notification_templates
	"000071": EditionEnterprise, // notification_outbox
	"000072": EditionEnterprise, // notification_events

	// AI Features
	"000073": EditionEnterprise, // ai_triage
	"000074": EditionEnterprise, // ai_triage_results

	// License Management
	"000075": EditionEnterprise, // license_keys
	"000076": EditionEnterprise, // modules

	// Reserved Enterprise (077-079)
	"000077": EditionEnterprise,
	"000078": EditionEnterprise,
	"000079": EditionEnterprise,

	// ========================================
	// SaaS Migrations - 000080 to 000099
	// ========================================

	// Platform Agents
	"000080": EditionSaaS, // platform_agents
	"000081": EditionSaaS, // agent_leases
	"000082": EditionSaaS, // platform_jobs
	"000083": EditionSaaS, // bootstrap_tokens
	"000084": EditionSaaS, // agent_registrations

	// Multi-tenancy
	"000085": EditionSaaS, // plans
	"000086": EditionSaaS, // subscriptions
	"000087": EditionSaaS, // invoices
	"000088": EditionSaaS, // usage_records

	// Platform Admin
	"000089": EditionSaaS, // admin_users
	"000090": EditionSaaS, // admin_audit_logs

	// Row-Level Security
	"000091": EditionSaaS, // tenant_rls_policies

	// Analytics
	"000092": EditionSaaS, // analytics_events
	"000093": EditionSaaS, // onboarding_progress

	// Reserved SaaS (094-099)
	"000094": EditionSaaS,
	"000095": EditionSaaS,
	"000096": EditionSaaS,
	"000097": EditionSaaS,
	"000098": EditionSaaS,
	"000099": EditionSaaS,

	// ========================================
	// Feature Migrations - 000100+
	// These are classified individually
	// ========================================
}

// GetMigrationEdition returns the edition for a migration number.
// Returns EditionCore if not classified (default safe behavior).
func GetMigrationEdition(version string) Edition {
	if edition, ok := MigrationClassification[version]; ok {
		return edition
	}
	// Default to core for unclassified migrations
	// This ensures backwards compatibility
	return EditionCore
}

// ShouldRunMigration checks if a migration should run for the given edition.
func ShouldRunMigration(migrationVersion string, targetEdition Edition) bool {
	migEdition := GetMigrationEdition(migrationVersion)

	switch targetEdition {
	case EditionCore:
		return migEdition == EditionCore
	case EditionEnterprise:
		return migEdition == EditionCore || migEdition == EditionEnterprise
	case EditionSaaS:
		return true // SaaS runs all migrations
	default:
		return migEdition == EditionCore
	}
}

// FilterMigrations filters a list of migration versions by edition.
func FilterMigrations(versions []string, edition Edition) []string {
	var filtered []string
	for _, v := range versions {
		if ShouldRunMigration(v, edition) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
