package tenant

// SectionFindingViews is the settings section key of FindingViewSettings.
const SectionFindingViews = "finding_views"

// FindingViewSettings are the organization's defaults for the findings work
// views (Active, My queue, SLA breached; docs/architecture/findings-work-views.md).
// A member's own preference overrides them.
type FindingViewSettings struct {
	// IncludeInformational shows informational findings (info and none) in
	// the work views. Off by default: they carry no SLA and no remediation
	// obligation. Needs triage leaves them out either way.
	IncludeInformational bool `json:"include_informational,omitempty"`
}

// UpdateFindingViewSettings updates only the findings work-view defaults.
func (t *Tenant) UpdateFindingViewSettings(fv FindingViewSettings) error {
	settings := t.TypedSettings()
	settings.FindingViews = fv
	return t.UpdateSettings(settings)
}
