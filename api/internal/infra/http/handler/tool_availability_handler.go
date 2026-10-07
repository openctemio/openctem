package handler

// GET /api/v1/tenant-tools/availability (docs/architecture/tool-availability.md).

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ToolAvailabilityZone is a scan zone a sensor is assigned to.
type ToolAvailabilityZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ToolAvailabilityContent is one piece of a tool's content on one sensor.
type ToolAvailabilityContent struct {
	Name      string  `json:"name"`
	Version   string  `json:"version,omitempty"`
	UpdatedAt *string `json:"updated_at,omitempty"`
}

// ToolAvailabilitySensor is one sensor that reports a tool installed.
type ToolAvailabilitySensor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// State is the sensor's state as the Sensors page shows it.
	State string `json:"state"`
	// Online: the sensor takes work now.
	Online  bool                      `json:"online"`
	Zones   []ToolAvailabilityZone    `json:"zones"`
	Version string                    `json:"version,omitempty"`
	Content []ToolAvailabilityContent `json:"content,omitempty"`
	// Excluded is why the sensor may not run the tool although it has it:
	// grant or local_policy; empty when it may.
	Excluded       string `json:"excluded,omitempty" enums:"grant,local_policy"`
	ExcludedDetail string `json:"excluded_detail,omitempty"`
}

// ToolContentVersionsResponse is the versions of one piece of a tool's
// content across the sensors that run it.
type ToolContentVersionsResponse struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

// ToolAvailabilityItem is one tool's availability for the tenant.
type ToolAvailabilityItem struct {
	Name string `json:"name"`
	// Tool is the catalog entry; null for a tool a sensor reports that the
	// tenant's catalog does not list.
	Tool      *ToolResponse `json:"tool"`
	InCatalog bool          `json:"in_catalog"`
	// Enabled: active in the catalog and switched on for the tenant.
	Enabled bool   `json:"enabled"`
	Status  string `json:"status" enums:"ready,no_sensor,offline_only,outdated,disabled"`
	// SensorsOnline / SensorsTotal count the sensors that may run the tool;
	// SensorsExcluded those that have it but may not.
	SensorsOnline   int `json:"sensors_online"`
	SensorsTotal    int `json:"sensors_total"`
	SensorsExcluded int `json:"sensors_excluded"`
	// Sensors lists every sensor that reports the tool, online first. Empty
	// without sensors:read (the counts are always given).
	Sensors            []ToolAvailabilitySensor      `json:"sensors"`
	Versions           []string                      `json:"versions"`
	MinReportedVersion string                        `json:"min_reported_version,omitempty"`
	MaxReportedVersion string                        `json:"max_reported_version,omitempty"`
	MinVersion         string                        `json:"min_version,omitempty"`
	LatestVersion      string                        `json:"latest_version,omitempty"`
	UpdateAvailable    bool                          `json:"update_available"`
	Content            []ToolContentVersionsResponse `json:"content"`
	LastReportedAt     *string                       `json:"last_reported_at,omitempty"`
}

// ToolAvailabilityResponse is the tenant's tool availability.
type ToolAvailabilityResponse struct {
	Items []ToolAvailabilityItem `json:"items"`
	// Summary counts the tools per status (every status present).
	Summary map[string]int `json:"summary"`
	// ZoneID is the scan zone the view is limited to.
	ZoneID     string `json:"zone_id,omitempty"`
	ComputedAt string `json:"computed_at"`
}

// ToolAvailability handles GET /api/v1/tenant-tools/availability
// @Summary      Tool availability
// @Description  Every catalog tool, plus every tool the tenant's sensors report, with the sensors that have it (online and total), the versions they report and a derived status. Sensor-reported data is advice: dispatch checks every job again at claim time.
// @Tags         Tenant Tools
// @Produce      json
// @Param        zone_id  query     string  false  "Only the sensors of this scan zone"
// @Success      200      {object}  ToolAvailabilityResponse
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/availability [get]
func (h *ToolHandler) ToolAvailability(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	res, err := h.service.ToolAvailability(r.Context(), tenantID, r.URL.Query().Get("zone_id"))
	switch {
	case errors.Is(err, shared.ErrNotFound):
		// The only lookup that can miss is the zone (another tenant's
		// zone reads as missing).
		apierror.NotFound("Scan zone").WriteJSON(w)
		return
	case err != nil:
		h.handleServiceError(w, err, "Tool availability")
		return
	}
	// Sensor names and zones are the Sensors page's data: listed only for
	// callers who may read sensors. The counts and status are for everyone
	// who may read the tenant's tools (the scan builder needs them).
	withSensors := middleware.HasPermission(r.Context(), permission.SensorsRead.String())

	resp := ToolAvailabilityResponse{
		Items:      make([]ToolAvailabilityItem, 0, len(res.Tools)),
		Summary:    make(map[string]int, len(res.Summary)),
		ComputedAt: res.ComputedAt.UTC().Format(time.RFC3339),
	}
	for st, n := range res.Summary {
		resp.Summary[string(st)] = n
	}
	if res.ZoneID != nil {
		resp.ZoneID = res.ZoneID.String()
	}
	for _, t := range res.Tools {
		resp.Items = append(resp.Items, toolAvailabilityItem(t, res, withSensors))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func toolAvailabilityItem(t tool.AvailableTool, res *tool.ToolAvailabilityResult, withSensors bool) ToolAvailabilityItem {
	item := ToolAvailabilityItem{
		Name:               t.Name,
		InCatalog:          t.InCatalog,
		Enabled:            t.Enabled,
		Status:             string(t.Status),
		SensorsOnline:      t.SensorsOnline,
		SensorsTotal:       t.SensorsTotal,
		SensorsExcluded:    t.SensorsExcluded,
		Sensors:            []ToolAvailabilitySensor{},
		Versions:           t.Versions,
		MinReportedVersion: t.MinReported,
		MaxReportedVersion: t.MaxReported,
		MinVersion:         t.MinVersion,
		LatestVersion:      t.LatestVersion,
		UpdateAvailable:    t.UpdateAvailable,
		Content:            make([]ToolContentVersionsResponse, 0, len(t.Content)),
		LastReportedAt:     formatTimePtr(t.LastReportedAt),
	}
	if item.Versions == nil {
		item.Versions = []string{}
	}
	if t.Tool != nil {
		item.Tool = toToolResponseWithCategory(t.Tool, t.Category)
	}
	for _, c := range t.Content {
		item.Content = append(item.Content, ToolContentVersionsResponse{Name: c.Name, Versions: c.Versions})
	}
	if !withSensors {
		return item
	}
	for _, s := range t.Sensors {
		item.Sensors = append(item.Sensors, toolAvailabilitySensor(s, res))
	}
	return item
}

func toolAvailabilitySensor(s sensor.ToolSensor, res *tool.ToolAvailabilityResult) ToolAvailabilitySensor {
	out := ToolAvailabilitySensor{
		ID: s.SensorID.String(), Name: s.Name, State: string(s.State), Online: s.Online,
		Zones: make([]ToolAvailabilityZone, 0, len(s.ZoneIDs)), Version: s.Version,
		Excluded: s.Excluded, ExcludedDetail: s.ExcludedDetail,
	}
	for _, z := range s.ZoneIDs {
		out.Zones = append(out.Zones, ToolAvailabilityZone{ID: z.String(), Name: res.Zones[z]})
	}
	sort.Slice(out.Zones, func(i, j int) bool { return out.Zones[i].Name < out.Zones[j].Name })
	for _, c := range s.Content {
		out.Content = append(out.Content, ToolAvailabilityContent{Name: c.Name, Version: c.Version, UpdatedAt: formatTimePtr(c.UpdatedAt)})
	}
	return out
}

// formatTimePtr formats an optional time as RFC 3339 UTC.
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}
