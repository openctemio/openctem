package audit

// Dashboard ownership actions (docs/architecture/dashboards.md). Every change
// to an organization dashboard is audited: those dashboards show
// organization-wide numbers and names to everyone in their audience. Plain
// views are not audited.
const (
	ActionDashboardOrgCreated      Action       = "dashboard.org_created"
	ActionDashboardOrgUpdated      Action       = "dashboard.org_updated"
	ActionDashboardOrgDeleted      Action       = "dashboard.org_deleted"
	ActionDashboardOrgDefaultSet   Action       = "dashboard.org_default_set"
	ActionDashboardOrgReordered    Action       = "dashboard.org_reordered"
	ActionDashboardAudienceChanged Action       = "dashboard.audience_changed"
	ActionDashboardScheduleChanged Action       = "dashboard.schedule_changed"
	ActionDashboardLayoutShared    Action       = "dashboard.layout_shared"
	ActionDashboardSettingsUpdated Action       = "dashboard.settings_updated"
	ActionRolePermissionMigrated   Action       = "role.permission_migrated"
	ResourceTypeDashboard          ResourceType = "dashboard"
)

var _ = registerActions("dashboard", map[Action]Severity{
	ActionDashboardOrgCreated:      SeverityLow,
	ActionDashboardOrgUpdated:      SeverityLow,
	ActionDashboardOrgDeleted:      SeverityMedium,
	ActionDashboardOrgDefaultSet:   SeverityLow,
	ActionDashboardOrgReordered:    SeverityLow,
	ActionDashboardAudienceChanged: SeverityMedium,
	ActionDashboardScheduleChanged: SeverityLow,
	ActionDashboardLayoutShared:    SeverityLow,
	ActionDashboardSettingsUpdated: SeverityLow,
})

// ActionRolePermissionMigrated is written by a migration that moves a role's
// grant from one permission to another (dashboard:aggregate to
// dashboards:org:view): high, because the new permission shows more.
var _ = registerActions("role", map[Action]Severity{
	ActionRolePermissionMigrated: SeverityHigh,
})
