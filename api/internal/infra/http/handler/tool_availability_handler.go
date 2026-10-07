package handler

// Tool availability in the tool view (GET /api/v1/tools?include=availability,
// docs/architecture/tool-availability.md).

import (
	"fmt"
	"sort"
	"time"

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
	// Trust is the tool's trust level on the sensor; empty when the sensor
	// reports no tool contract.
	Trust string `json:"trust,omitempty" enums:"builtin,unverified"`
	// Tier is the tier the platform assigns a scan with the tool there.
	Tier string `json:"tier" enums:"T0,T1,T2"`
}

// ToolContentVersionsResponse is the versions of one piece of a tool's
// content across the sensors that run it.
type ToolContentVersionsResponse struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

// ToolAvailabilityInfo is one tool's availability for the organization,
// computed from what its sensors report (advice: dispatch checks every job
// again at claim time).
type ToolAvailabilityInfo struct {
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
	// Trust is the lowest trust among the sensors that can run the tool
	// (unverified: one runs an operator-installed copy); empty when none
	// reports a contract.
	Trust string `json:"trust,omitempty" enums:"builtin,unverified"`
	// Tier is the highest tier the platform assigns a scan with the tool on
	// those sensors; empty when no sensor can run it.
	Tier string `json:"tier,omitempty" enums:"T0,T1,T2"`
}

// UnlistedToolResponse is a tool the sensors report that the catalog does
// not list.
type UnlistedToolResponse struct {
	Name string `json:"name"`
	ToolAvailabilityInfo
}

// toToolAvailabilityInfo converts one tool's availability. Sensor names and
// zones are the Sensors page's data: listed only withSensors (sensors:read);
// the counts and status are for everyone who may read the tenant's tools.
func toToolAvailabilityInfo(t sensor.ToolAvailability, zones map[shared.ID]string, withSensors bool) ToolAvailabilityInfo {
	item := ToolAvailabilityInfo{
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
		Trust:              t.Trust,
		Tier:               tierLabel(t.Tier),
	}
	if item.Versions == nil {
		item.Versions = []string{}
	}
	for _, c := range t.Content {
		item.Content = append(item.Content, ToolContentVersionsResponse{Name: c.Name, Versions: c.Versions})
	}
	if !withSensors {
		return item
	}
	for _, s := range t.Sensors {
		item.Sensors = append(item.Sensors, toolAvailabilitySensor(s, zones))
	}
	return item
}

func toolAvailabilitySensor(s sensor.ToolSensor, zones map[shared.ID]string) ToolAvailabilitySensor {
	out := ToolAvailabilitySensor{
		ID: s.SensorID.String(), Name: s.Name, State: string(s.State), Online: s.Online,
		Zones: make([]ToolAvailabilityZone, 0, len(s.ZoneIDs)), Version: s.Version,
		Excluded: s.Excluded, ExcludedDetail: s.ExcludedDetail,
		Trust: s.Trust, Tier: tierLabel(s.Tier),
	}
	for _, z := range s.ZoneIDs {
		out.Zones = append(out.Zones, ToolAvailabilityZone{ID: z.String(), Name: zones[z]})
	}
	sort.Slice(out.Zones, func(i, j int) bool { return out.Zones[i].Name < out.Zones[j].Name })
	for _, c := range s.Content {
		out.Content = append(out.Content, ToolAvailabilityContent{Name: c.Name, Version: c.Version, UpdatedAt: formatTimePtr(c.UpdatedAt)})
	}
	return out
}

// tierLabel is "T0".."T2" ("" for no tier).
func tierLabel(t int) string {
	if t < sensor.TierPassive || t > sensor.TierIntrusive {
		return ""
	}
	return fmt.Sprintf("T%d", t)
}

// formatTimePtr formats an optional time as RFC 3339 UTC.
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}
