package tool

// The tenant's view of the tool catalog (GET /api/v1/tools,
// docs/architecture/tool-availability.md): platform tools plus the tenant's
// own custom tools, each with what the caller asked to include (the tenant's
// settings, the availability from its sensors, its run statistics).
//
// Security: the catalog is read for the caller's tenant only (platform tools
// and its own custom tools, never another tenant's); a tool id outside that
// set reads as not found. Settings, availability and statistics are the
// tenant's own rows. What the HTTP layer may show of them (sensor names,
// settings) it decides from the caller's permissions.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Tool sources: a platform tool (shared by every tenant, managed by the
// platform) or a custom tool (owned by one tenant).
const (
	SourcePlatform = "platform"
	SourceCustom   = "custom"
)

// ToolSortFields are the sort keys of the tool list ("-" prefix: descending).
var ToolSortFields = map[string]bool{"name": true, "created_at": true, "updated_at": true}

// ToolViewOptions says what to add to each tool of the view.
type ToolViewOptions struct {
	// Availability adds the availability from the tenant's sensors, limited
	// to ZoneID's sensors when set.
	Availability bool
	ZoneID       string
	// Stats adds the run statistics of the last StatsDays days (1..365, 30
	// when 0).
	Stats     bool
	StatsDays int
}

// ListToolViewInput is the input of ListToolView.
type ListToolViewInput struct {
	TenantID string
	// Source: SourcePlatform, SourceCustom or "" (both).
	Source   string
	Category string
	Search   string
	// Enabled filters on the tenant's switch (active in the catalog and on
	// for the tenant); Available on whether a scan job can be dispatched now.
	Enabled   *bool
	Available *bool
	// Sort: a ToolSortFields key, "-" for descending; "" is the catalog
	// order (category, then display name).
	Sort    string
	Page    int
	PerPage int
	ToolViewOptions
}

// ToolView is one tool of the tenant's view.
type ToolView struct {
	*tooldom.ToolWithConfig
	// Availability is nil unless requested.
	Availability *sensor.ToolAvailability
	// Stats is nil unless requested.
	Stats *tooldom.ToolStats
	// Zones names the scan zones of the sensors in Availability.
	Zones map[shared.ID]string
}

// ToolViewList is a page of the tenant's view.
type ToolViewList struct {
	pagination.Result[*ToolView]
	// Availability is the whole availability view (every tool, filters not
	// applied): its summary and the tools the sensors report that the
	// catalog does not list. Nil unless requested.
	Availability *ToolAvailabilityResult
	Unlisted     []AvailableTool
}

// ListToolView lists the tenant's view of the catalog with filters, sort and
// pagination.
func (s *Service) ListToolView(ctx context.Context, input ListToolViewInput) (*ToolViewList, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	switch input.Source {
	case "", SourcePlatform, SourceCustom:
	default:
		return nil, fmt.Errorf("%w: source must be platform or custom", shared.ErrValidation)
	}
	sortField, desc := strings.TrimPrefix(input.Sort, "-"), strings.HasPrefix(input.Sort, "-")
	if input.Sort != "" && !ToolSortFields[sortField] {
		return nil, fmt.Errorf("%w: unknown sort field %q", shared.ErrValidation, sortField)
	}

	filter := tooldom.ToolFilter{Search: input.Search}
	if input.Category != "" {
		filter.CategoryName = &input.Category
	}
	catalog, err := s.catalog(ctx, tid, filter)
	if err != nil {
		return nil, err
	}

	out := &ToolViewList{}
	var byName map[string]*sensor.ToolAvailability
	if input.Availability || input.Available != nil {
		res, err := s.ToolAvailability(ctx, input.TenantID, input.ZoneID)
		if err != nil {
			return nil, err
		}
		byName = make(map[string]*sensor.ToolAvailability, len(res.Tools))
		for i := range res.Tools {
			if res.Tools[i].InCatalog {
				byName[res.Tools[i].Name] = &res.Tools[i].ToolAvailability
			} else {
				out.Unlisted = append(out.Unlisted, res.Tools[i])
			}
		}
		if input.Availability {
			out.Availability = res
		} else {
			out.Unlisted = nil
		}
	}

	views := make([]*ToolView, 0, len(catalog))
	for _, twc := range catalog {
		if !matchesSource(twc.Tool, input.Source) {
			continue
		}
		if input.Enabled != nil && (twc.Tool.IsActive && twc.IsEnabled) != *input.Enabled {
			continue
		}
		ta := byName[twc.Tool.Name]
		if input.Available != nil && s.runnable(ta) != *input.Available {
			continue
		}
		v := &ToolView{ToolWithConfig: twc}
		if input.Availability {
			v.Availability, v.Zones = ta, out.Availability.Zones
		}
		views = append(views, v)
	}
	sortToolViews(views, sortField, desc)

	page := pagination.New(input.Page, input.PerPage)
	out.Result = pagination.NewResult(pageOf(views, page), int64(len(views)), page)
	if input.Stats {
		if err := s.addStats(ctx, tid, out.Data, input.StatsDays); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetToolView returns one tool of the tenant's view: a platform tool or the
// tenant's own custom tool; any other id is not found.
func (s *Service) GetToolView(ctx context.Context, tenantID, toolID string, opts ToolViewOptions) (*ToolView, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	twc, err := s.GetToolWithConfig(ctx, tenantID, toolID)
	if err != nil {
		return nil, err
	}
	v := &ToolView{ToolWithConfig: twc}
	if opts.Availability {
		res, err := s.ToolAvailability(ctx, tenantID, opts.ZoneID)
		if err != nil {
			return nil, err
		}
		v.Zones = res.Zones
		for i := range res.Tools {
			if res.Tools[i].InCatalog && res.Tools[i].Name == twc.Tool.Name {
				v.Availability = &res.Tools[i].ToolAvailability
				break
			}
		}
	}
	if opts.Stats {
		if err := s.addStats(ctx, tid, []*ToolView{v}, opts.StatsDays); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// UpdateToolSettingsInput changes the tenant's settings of one tool. A nil
// field is left as it is; an empty Config clears the tenant's overrides.
type UpdateToolSettingsInput struct {
	TenantID  string
	ToolID    string
	IsEnabled *bool
	Config    map[string]any
	UpdatedBy string
}

// UpdateToolSettings changes the tenant's switch and config overrides of a
// tool it may see (a platform tool or its own custom tool).
func (s *Service) UpdateToolSettings(ctx context.Context, input UpdateToolSettingsInput) (*tooldom.TenantToolConfig, error) {
	if input.IsEnabled == nil && input.Config == nil {
		return nil, fmt.Errorf("%w: nothing to change (is_enabled or config)", shared.ErrValidation)
	}
	// The current settings: a tool the tenant never configured is enabled,
	// without overrides.
	enabled, config := true, map[string]any{}
	if cur, err := s.GetTenantToolConfig(ctx, input.TenantID, input.ToolID); err == nil && cur != nil {
		enabled, config = cur.IsEnabled, cur.Config
	}
	if input.IsEnabled != nil {
		enabled = *input.IsEnabled
	}
	if input.Config != nil {
		// Settings never hold secrets: a credential belongs in the secret
		// store, referenced by id. Refuse a config with a secret-shaped key
		// or value (the same detector as scan configs), naming only paths.
		if found := scan.DetectConfigSecrets(input.Config); len(found) > 0 {
			paths := make([]string, 0, len(found))
			for _, f := range found {
				paths = append(paths, f.Path)
			}
			return nil, fmt.Errorf("%w: config holds a secret at %s; store it in the secret store and reference it by id",
				shared.ErrValidation, strings.Join(paths, ", "))
		}
		config = input.Config
	}
	return s.UpdateTenantToolConfig(ctx, UpdateTenantToolConfigInput{
		TenantID:  input.TenantID,
		ToolID:    input.ToolID,
		Config:    config,
		IsEnabled: enabled,
		UpdatedBy: input.UpdatedBy,
	})
}

// catalog reads the tenant's catalog (platform tools and its own custom
// tools) matching filter, with the tenant's settings.
func (s *Service) catalog(ctx context.Context, tenantID shared.ID, filter tooldom.ToolFilter) ([]*tooldom.ToolWithConfig, error) {
	var all []*tooldom.ToolWithConfig
	for page := 1; len(all) < maxCatalogTools; page++ {
		res, err := s.configRepo.ListToolsWithConfig(ctx, tenantID, filter, pagination.New(page, catalogPageSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read the tool catalog: %w", err)
		}
		all = append(all, res.Data...)
		if len(res.Data) < catalogPageSize || int64(len(all)) >= res.Total {
			break
		}
	}
	return all, nil
}

// runnable: a scan job for the tool can be dispatched now; every tool when
// availability is not wired (unknown), as the scan pickers expect.
func (s *Service) runnable(ta *sensor.ToolAvailability) bool {
	if s.availSensors == nil {
		return true
	}
	return ta != nil && ta.Runnable()
}

// addStats sets the run statistics of each view (zero for a tool without
// runs) from one tenant-wide query.
func (s *Service) addStats(ctx context.Context, tenantID shared.ID, views []*ToolView, days int) error {
	if len(views) == 0 {
		return nil
	}
	if days <= 0 {
		days = 30
	}
	if days > 365 {
		days = 365
	}
	st, err := s.executionRepo.GetTenantStats(ctx, tenantID, days)
	if err != nil {
		return fmt.Errorf("failed to read tool statistics: %w", err)
	}
	byTool := make(map[shared.ID]tooldom.ToolStats, len(st.ToolBreakdown))
	for _, b := range st.ToolBreakdown {
		byTool[b.ToolID] = b
	}
	for _, v := range views {
		ts, ok := byTool[v.Tool.ID]
		if !ok {
			ts = tooldom.ToolStats{ToolID: v.Tool.ID}
		}
		v.Stats = &ts
	}
	return nil
}

func matchesSource(t *tooldom.Tool, source string) bool {
	switch source {
	case SourcePlatform:
		return t.IsPlatformTool()
	case SourceCustom:
		return !t.IsPlatformTool()
	}
	return true
}

func sortToolViews(views []*ToolView, field string, desc bool) {
	if field == "" {
		return // the catalog order
	}
	less := func(a, b *tooldom.Tool) bool {
		switch field {
		case "created_at":
			return a.CreatedAt.Before(b.CreatedAt)
		case "updated_at":
			return a.UpdatedAt.Before(b.UpdatedAt)
		}
		return strings.ToLower(displayName(a)) < strings.ToLower(displayName(b))
	}
	sort.SliceStable(views, func(i, j int) bool {
		if desc {
			return less(views[j].Tool, views[i].Tool)
		}
		return less(views[i].Tool, views[j].Tool)
	})
}

func displayName(t *tooldom.Tool) string {
	if t.DisplayName != "" {
		return t.DisplayName
	}
	return t.Name
}

func pageOf(views []*ToolView, p pagination.Pagination) []*ToolView {
	start := p.Offset()
	if start >= len(views) {
		return []*ToolView{}
	}
	end := start + p.Limit()
	if end > len(views) {
		end = len(views)
	}
	return views[start:end]
}
