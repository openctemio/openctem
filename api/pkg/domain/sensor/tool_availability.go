package sensor

// Tool availability (docs/architecture/tool-availability.md): for each tool a
// tenant could scan with, which of the tenant's sensors really have it,
// whether any of them takes work now, and what versions they report.
//
// The inventory is what the sensors reported in their manifests (the
// reported_* projection on the sensor row), so it is display and advice
// only: the claim-time gates (dispatch tools, the grant, the sensor-local
// policy) stay authoritative for every job.

import (
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ToolStatus is a tool's availability for a tenant, derived on read.
type ToolStatus string

const (
	// ToolReady: enabled, and at least one sensor that takes work now has it
	// (at the catalog's minimum version when one is set).
	ToolReady ToolStatus = "ready"
	// ToolNoSensor: enabled, but no sensor of the tenant reports it.
	ToolNoSensor ToolStatus = "no_sensor"
	// ToolOfflineOnly: enabled; sensors report it, but none takes work now.
	ToolOfflineOnly ToolStatus = "offline_only"
	// ToolOutdated: enabled and on online sensors, but every one of them
	// reports a version below the catalog's minimum.
	ToolOutdated ToolStatus = "outdated"
	// ToolDisabled: the tenant (or the catalog) switched the tool off.
	ToolDisabled ToolStatus = "disabled"
)

// AllToolStatuses lists every status, for stable summaries.
func AllToolStatuses() []ToolStatus {
	return []ToolStatus{ToolReady, ToolNoSensor, ToolOfflineOnly, ToolOutdated, ToolDisabled}
}

// Why a sensor that reports a tool installed still cannot run it.
const (
	// ToolExcludedGrant: the sensor's grant refuses a scan with the tool
	// (job types, tools, or the tool's tier above the ceiling).
	ToolExcludedGrant = "grant"
	// ToolExcludedLocalPolicy: the sensor's own local policy refuses a scan
	// with the tool (its tool or job list, or the kill switch).
	ToolExcludedLocalPolicy = "local_policy"
)

// MaxToolVersionsListed bounds the distinct versions listed per tool and
// per piece of content.
const MaxToolVersionsListed = 20

// CatalogTool is one catalog entry as the availability view needs it.
type CatalogTool struct {
	Name string
	// Enabled: active in the catalog and not switched off by the tenant.
	Enabled bool
	// MinVersion is the oldest version the catalog accepts ("" = none).
	MinVersion string
	// LatestVersion is the newest version the catalog knows ("" = none).
	LatestVersion string
}

// SensorInventory is one sensor's reported tools with what limits them.
type SensorInventory struct {
	Sensor *Sensor
	// Grant is the sensor's grant; nil when none was read (no limit).
	Grant *Grant
	// ZoneIDs are the scan zones the sensor is assigned to.
	ZoneIDs []shared.ID
}

// ToolSensor is one sensor that reports a tool installed.
type ToolSensor struct {
	SensorID shared.ID
	Name     string
	State    State
	// Online: the sensor takes work now (State.TakesJobs, not one-shot).
	Online  bool
	ZoneIDs []shared.ID
	// Version is the tool version the sensor reported ("" = none).
	Version string
	Content []ReportedContent
	// Excluded is why the sensor cannot run the tool although it has it
	// (ToolExcluded*); "" when it can. ExcludedDetail says what refused.
	Excluded       string
	ExcludedDetail string
}

// ToolContentVersions is the versions of one piece of a tool's content
// (nuclei templates, the trivy database) across the sensors that run it.
type ToolContentVersions struct {
	Name     string
	Versions []string
}

// ToolAvailability is one tool's availability for a tenant.
type ToolAvailability struct {
	Name string
	// InCatalog is false for a tool a sensor reports that the tenant's
	// catalog does not list (shown, never enabled).
	InCatalog bool
	Enabled   bool
	Status    ToolStatus
	// SensorsOnline and SensorsTotal count the sensors that can run the
	// tool (not excluded); SensorsExcluded those that have it but may not.
	SensorsOnline   int
	SensorsTotal    int
	SensorsExcluded int
	Sensors         []ToolSensor
	// Versions are the distinct versions the runnable sensors report,
	// oldest first; MinReported and MaxReported their ends.
	Versions    []string
	MinReported string
	MaxReported string
	Content     []ToolContentVersions
	// LastReportedAt is the newest report among the sensors listed.
	LastReportedAt *time.Time
	MinVersion     string
	// LatestVersion is the newest version known: the catalog's, or the
	// newest a sensor reports when that is newer.
	LatestVersion string
	// UpdateAvailable: a runnable sensor reports a version below
	// LatestVersion.
	UpdateAvailable bool
}

// toolExclusion is why the sensor may not run a scan with a tool it reports
// installed, and the detail: the same rules admission applies to a scan job
// for the tool (the grant's Admit, the local policy's Accepts), asked for a
// job without targets in zoneID (nil: unzoned). The administrator narrows a
// sensor's tools through its grant.
func toolExclusion(inv SensorInventory, name string, zoneID *shared.ID) (reason, detail string) {
	a := inv.Sensor
	payload, _ := json.Marshal(map[string]string{"scanner": name})
	if inv.Grant != nil {
		if r := inv.Grant.Admit(scanJobType, payload, zoneID); r != nil {
			return ToolExcludedGrant, r.Error()
		}
	}
	if r := Accepts(a.LocalPolicy, JobOf(scanJobType, payload), DispatchOptions{}); r != nil {
		return ToolExcludedLocalPolicy, r.Detail
	}
	return "", ""
}

// scanJobType is the command type of a scan job.
const scanJobType = "scan"

// ComputeToolAvailability joins the catalog with the sensors' reported
// inventories. Every catalog tool is listed, plus every tool a sensor
// reports that the catalog does not list. zoneID, when set, keeps only the
// sensors assigned to that zone. The result is sorted by name.
func ComputeToolAvailability(catalog []CatalogTool, sensors []SensorInventory, zoneID *shared.ID, now time.Time) []ToolAvailability {
	byName := make(map[string]*ToolAvailability, len(catalog))
	order := make([]string, 0, len(catalog))
	for _, c := range catalog {
		if _, dup := byName[c.Name]; dup || c.Name == "" {
			continue
		}
		byName[c.Name] = &ToolAvailability{Name: c.Name, InCatalog: true, Enabled: c.Enabled,
			MinVersion: NormalizeVersion(c.MinVersion), LatestVersion: NormalizeVersion(c.LatestVersion)}
		order = append(order, c.Name)
	}

	for _, inv := range sensors {
		a := inv.Sensor
		if a == nil || a.Status != SensorStatusActive || a.Reported.Tools == nil {
			continue
		}
		if zoneID != nil && !slices.Contains(inv.ZoneIDs, *zoneID) {
			continue
		}
		online := a.CanTakeJobs(now)
		state := a.AssessHealth(now, DefaultHealthPolicy()).State
		for _, rt := range a.Reported.Tools {
			if !rt.Installed || rt.Name == "" {
				continue
			}
			t, ok := byName[rt.Name]
			if !ok {
				t = &ToolAvailability{Name: rt.Name}
				byName[rt.Name] = t
				order = append(order, rt.Name)
			}
			ts := ToolSensor{SensorID: a.ID, Name: a.Name, State: state, Online: online,
				ZoneIDs: inv.ZoneIDs, Version: NormalizeVersion(rt.Version), Content: rt.Content}
			ts.Excluded, ts.ExcludedDetail = toolExclusion(inv, rt.Name, zoneID)
			t.Sensors = append(t.Sensors, ts)
			if a.Reported.ReportedAt != nil && (t.LastReportedAt == nil || a.Reported.ReportedAt.After(*t.LastReportedAt)) {
				at := *a.Reported.ReportedAt
				t.LastReportedAt = &at
			}
		}
	}

	out := make([]ToolAvailability, 0, len(order))
	for _, name := range order {
		t := byName[name]
		t.finish()
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// finish derives the counts, versions and status from the sensors listed.
func (t *ToolAvailability) finish() {
	sort.SliceStable(t.Sensors, func(i, j int) bool {
		if t.Sensors[i].Online != t.Sensors[j].Online {
			return t.Sensors[i].Online
		}
		return t.Sensors[i].Name < t.Sensors[j].Name
	})
	versions := map[string]bool{}
	content := map[string]map[string]bool{}
	var contentOrder []string
	meetsMin := false
	for _, s := range t.Sensors {
		if s.Excluded != "" {
			t.SensorsExcluded++
			continue
		}
		t.SensorsTotal++
		if s.Version != "" {
			versions[s.Version] = true
		}
		for _, c := range s.Content {
			if content[c.Name] == nil {
				content[c.Name] = map[string]bool{}
				contentOrder = append(contentOrder, c.Name)
			}
			if c.Version != "" {
				content[c.Name][c.Version] = true
			}
		}
		if !s.Online {
			continue
		}
		t.SensorsOnline++
		// A sensor that reports no version cannot be told outdated.
		if t.MinVersion == "" || s.Version == "" || CompareVersions(s.Version, t.MinVersion) >= 0 {
			meetsMin = true
		}
	}

	t.Versions = sortedVersions(versions)
	if n := len(t.Versions); n > 0 {
		t.MinReported, t.MaxReported = t.Versions[0], t.Versions[n-1]
		if IsReleaseVersion(t.MaxReported) && (t.LatestVersion == "" || CompareVersions(t.MaxReported, t.LatestVersion) > 0) {
			t.LatestVersion = t.MaxReported
		}
		if IsReleaseVersion(t.LatestVersion) && IsReleaseVersion(t.MinReported) &&
			CompareVersions(t.MinReported, t.LatestVersion) < 0 {
			t.UpdateAvailable = true
		}
	}
	sort.Strings(contentOrder)
	for _, name := range contentOrder {
		t.Content = append(t.Content, ToolContentVersions{Name: name, Versions: sortedVersions(content[name])})
	}

	switch {
	case !t.Enabled:
		t.Status = ToolDisabled
	case t.SensorsTotal == 0:
		t.Status = ToolNoSensor
	case t.SensorsOnline == 0:
		t.Status = ToolOfflineOnly
	case !meetsMin:
		t.Status = ToolOutdated
	default:
		t.Status = ToolReady
	}
}

// Runnable reports whether a job for the tool can be dispatched now:
// enabled and on at least one online sensor that may run it.
func (t ToolAvailability) Runnable() bool {
	return t.Status == ToolReady || t.Status == ToolOutdated
}

// sortedVersions returns the set's versions oldest first, at most
// MaxToolVersionsListed (the newest ones).
func sortedVersions(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) < 0 })
	if len(out) > MaxToolVersionsListed {
		out = out[len(out)-MaxToolVersionsListed:]
	}
	return out
}

// SummarizeToolStatuses counts the tools per status (every status present).
func SummarizeToolStatuses(tools []ToolAvailability) map[ToolStatus]int {
	out := make(map[ToolStatus]int, len(AllToolStatuses()))
	for _, st := range AllToolStatuses() {
		out[st] = 0
	}
	for _, t := range tools {
		out[t.Status]++
	}
	return out
}
