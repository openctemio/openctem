package audit

// "Rebuild dashboard data" (api/docs/architecture/dashboards.md, "Facts
// maintainer"): recomputes the organization's derived dashboard facts.

const (
	// ActionDashboardDataRebuildRequested records a rebuild request, from the
	// organization or from the console.
	ActionDashboardDataRebuildRequested Action = "dashboard_data.rebuild_requested"
)

// ResourceTypeDashboardData is the organization's dashboard fact data.
const ResourceTypeDashboardData ResourceType = "dashboard_data"

var _ = registerActions("dashboard_data", map[Action]Severity{
	ActionDashboardDataRebuildRequested: SeverityLow,
})

func init() {
	configResourceTypes[ResourceTypeDashboardData] = struct{}{}
}
