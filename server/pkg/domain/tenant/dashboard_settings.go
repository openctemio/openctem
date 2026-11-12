package tenant

// SectionDashboards is the settings section key of the dashboard defaults.
const SectionDashboards = "dashboards"

// DashboardSettings are the organization's dashboard defaults
// (docs/architecture/dashboards.md). The dashboard service validates them
// (known cadence, not below the organization's refresh floor) before they
// are stored.
type DashboardSettings struct {
	// DefaultRefreshSchedule is the cadence of every dashboard that has none
	// of its own: manual, 5m, 15m, 1h, 6h or daily. Empty means 1h.
	DefaultRefreshSchedule string `json:"default_refresh_schedule,omitempty"`
	// DefaultRefreshDailyMinute is the minute of the day (UTC) of a daily
	// default refresh.
	DefaultRefreshDailyMinute *int `json:"default_refresh_daily_minute,omitempty"`
}

// UpdateDashboardSettings updates only the dashboard defaults.
func (t *Tenant) UpdateDashboardSettings(ds DashboardSettings) error {
	settings := t.TypedSettings()
	settings.Dashboards = ds
	return t.UpdateSettings(settings)
}
