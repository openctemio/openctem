package sensor

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// availSensor is an active daemon sensor last seen at lastSeen that reports
// tools (name -> version) installed.
func availSensor(name string, lastSeen *time.Time, tools map[string]string) *Sensor {
	a := daemon(lastSeen)
	a.ID = shared.NewID()
	a.Name = name
	a.Tools = nil
	reported := testNow.Add(-time.Minute)
	a.Reported = CapabilityReport{Tools: []ReportedTool{}, ReportedAt: &reported}
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		a.Reported.Tools = append(a.Reported.Tools, ReportedTool{Name: n, Version: tools[n], Installed: true})
	}
	return a
}

func findTool(t *testing.T, list []ToolAvailability, name string) ToolAvailability {
	t.Helper()
	for _, ta := range list {
		if ta.Name == name {
			return ta
		}
	}
	t.Fatalf("tool %q not listed in %+v", name, list)
	return ToolAvailability{}
}

func TestComputeToolAvailability_Statuses(t *testing.T) {
	online := availSensor("edge-1", ago(5*time.Second), map[string]string{"nuclei": "3.4.2", "trivy": "0.50.0"})
	offline := availSensor("edge-2", ago(2*time.Hour), map[string]string{"semgrep": "1.80.0", "nuclei": "3.3.0"})
	offline.Health = SensorHealthOffline

	catalog := []CatalogTool{
		{Name: "nuclei", Enabled: true},
		{Name: "trivy", Enabled: true, MinVersion: "0.55.0"},
		{Name: "semgrep", Enabled: true},
		{Name: "checkov", Enabled: true},
		{Name: "gitleaks", Enabled: false},
	}
	got := ComputeToolAvailability(catalog, []SensorInventory{{Sensor: online}, {Sensor: offline}}, nil, testNow)

	cases := map[string]ToolStatus{
		"nuclei":   ToolReady,
		"trivy":    ToolOutdated,
		"semgrep":  ToolOfflineOnly,
		"checkov":  ToolNoSensor,
		"gitleaks": ToolDisabled,
	}
	for name, want := range cases {
		if st := findTool(t, got, name).Status; st != want {
			t.Errorf("%s: status %q, want %q", name, st, want)
		}
	}

	n := findTool(t, got, "nuclei")
	if n.SensorsOnline != 1 || n.SensorsTotal != 2 {
		t.Errorf("nuclei: %d/%d online, want 1/2", n.SensorsOnline, n.SensorsTotal)
	}
	if n.Sensors[0].Name != "edge-1" || !n.Sensors[0].Online {
		t.Errorf("nuclei: online sensor not listed first: %+v", n.Sensors)
	}
	if n.MinReported != "v3.3.0" || n.MaxReported != "v3.4.2" || len(n.Versions) != 2 {
		t.Errorf("nuclei versions = %v (%s..%s)", n.Versions, n.MinReported, n.MaxReported)
	}
	// The newest reported version is the latest known; edge-2 is behind it.
	if n.LatestVersion != "v3.4.2" || !n.UpdateAvailable {
		t.Errorf("nuclei latest %q update %v, want v3.4.2 true", n.LatestVersion, n.UpdateAvailable)
	}
	if n.LastReportedAt == nil {
		t.Error("nuclei: last reported time missing")
	}

	summary := SummarizeToolStatuses(got)
	for _, st := range AllToolStatuses() {
		if summary[st] != 1 {
			t.Errorf("summary[%s] = %d, want 1", st, summary[st])
		}
	}
}

func TestComputeToolAvailability_SensorAdvertisedToolOutsideCatalog(t *testing.T) {
	a := availSensor("edge-1", ago(5*time.Second), map[string]string{"my-scanner": "1.0.0"})
	got := ComputeToolAvailability(nil, []SensorInventory{{Sensor: a}}, nil, testNow)
	ta := findTool(t, got, "my-scanner")
	if ta.InCatalog || ta.Enabled || ta.Status != ToolDisabled || ta.SensorsOnline != 1 {
		t.Errorf("unlisted tool = %+v, want listed, not in catalog, disabled, 1 online", ta)
	}
}

func TestComputeToolAvailability_Exclusions(t *testing.T) {
	admin := availSensor("narrowed", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	admin.Tools = []string{"trivy"} // the administrator's list leaves nuclei out
	granted := availSensor("granted", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	local := availSensor("local", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	local.LocalPolicy = &LocalPolicyReport{State: LocalPolicyEnforced, Summary: &LocalPolicySummary{Tools: []string{"semgrep"}}}

	got := ComputeToolAvailability([]CatalogTool{{Name: "nuclei", Enabled: true}}, []SensorInventory{
		{Sensor: admin},
		{Sensor: granted, Grant: &Grant{TrustLevel: TrustTrusted, TierCeiling: TierIntrusive, Tools: []string{"trivy"}}},
		{Sensor: local},
	}, nil, testNow)
	n := findTool(t, got, "nuclei")
	if n.SensorsTotal != 0 || n.SensorsExcluded != 3 || n.Status != ToolNoSensor {
		t.Fatalf("nuclei = total %d excluded %d status %s, want 0 3 no_sensor", n.SensorsTotal, n.SensorsExcluded, n.Status)
	}
	want := map[string]string{"narrowed": ToolExcludedSensorSettings, "granted": ToolExcludedGrant, "local": ToolExcludedLocalPolicy}
	for _, s := range n.Sensors {
		if s.Excluded != want[s.Name] || s.ExcludedDetail == "" {
			t.Errorf("%s excluded %q (%q), want %q with a detail", s.Name, s.Excluded, s.ExcludedDetail, want[s.Name])
		}
	}

	// A New sensor's grant stops at passive tools: nuclei (active) is
	// refused by the tier ceiling even with no tool list.
	newSensor := availSensor("new", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	got = ComputeToolAvailability([]CatalogTool{{Name: "nuclei", Enabled: true}}, []SensorInventory{
		{Sensor: newSensor, Grant: &Grant{TrustLevel: TrustNew, TierCeiling: TierIntrusive}},
	}, nil, testNow)
	if s := findTool(t, got, "nuclei").Sensors[0]; s.Excluded != ToolExcludedGrant {
		t.Errorf("new sensor: excluded %q, want grant (tier ceiling)", s.Excluded)
	}
	// A broad trusted grant refuses nothing.
	got = ComputeToolAvailability([]CatalogTool{{Name: "nuclei", Enabled: true}}, []SensorInventory{
		{Sensor: newSensor, Grant: &Grant{TrustLevel: TrustTrusted, TierCeiling: TierIntrusive}},
	}, nil, testNow)
	if n := findTool(t, got, "nuclei"); n.SensorsOnline != 1 || n.Status != ToolReady {
		t.Errorf("trusted broad grant: %+v, want 1 online, ready", n)
	}
}

func TestComputeToolAvailability_ZoneFilterAndSkippedSensors(t *testing.T) {
	zoneA, zoneB := shared.NewID(), shared.NewID()
	inA := availSensor("in-a", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	inB := availSensor("in-b", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	never := availSensor("never-reported", ago(5*time.Second), nil)
	never.Reported.Tools = nil
	never.Tools = []string{"nuclei"} // declared only: not an inventory
	disabled := availSensor("disabled", ago(5*time.Second), map[string]string{"nuclei": "3.4.2"})
	disabled.Status = SensorStatusDisabled
	notInstalled := availSensor("not-installed", ago(5*time.Second), map[string]string{"nuclei": ""})
	notInstalled.Reported.Tools[0].Installed = false

	inv := []SensorInventory{
		{Sensor: inA, ZoneIDs: []shared.ID{zoneA}},
		{Sensor: inB, ZoneIDs: []shared.ID{zoneB}},
		{Sensor: never, ZoneIDs: []shared.ID{zoneA}},
		{Sensor: disabled, ZoneIDs: []shared.ID{zoneA}},
		{Sensor: notInstalled, ZoneIDs: []shared.ID{zoneA}},
	}
	catalog := []CatalogTool{{Name: "nuclei", Enabled: true}}

	all := findTool(t, ComputeToolAvailability(catalog, inv, nil, testNow), "nuclei")
	if all.SensorsTotal != 2 {
		t.Errorf("unfiltered total %d, want 2 (declared-only, disabled and not-installed skipped)", all.SensorsTotal)
	}
	inZone := findTool(t, ComputeToolAvailability(catalog, inv, &zoneA, testNow), "nuclei")
	if inZone.SensorsTotal != 1 || inZone.Sensors[0].Name != "in-a" {
		t.Errorf("zone A sensors = %+v, want only in-a", inZone.Sensors)
	}
	empty := shared.NewID()
	if st := findTool(t, ComputeToolAvailability(catalog, inv, &empty, testNow), "nuclei").Status; st != ToolNoSensor {
		t.Errorf("zone without sensors: status %s, want no_sensor", st)
	}
}

func TestComputeToolAvailability_OneShotIsNeverOnline(t *testing.T) {
	ci := availSensor("ci", ago(5*time.Second), map[string]string{"semgrep": "1.80.0"})
	ci.ExecutionMode = ExecutionModeStandalone
	ta := findTool(t, ComputeToolAvailability([]CatalogTool{{Name: "semgrep", Enabled: true}},
		[]SensorInventory{{Sensor: ci}}, nil, testNow), "semgrep")
	if ta.SensorsOnline != 0 || ta.Status != ToolOfflineOnly {
		t.Errorf("one-shot sensor: %d online, status %s; want 0, offline_only", ta.SensorsOnline, ta.Status)
	}
}

func TestComputeToolAvailability_UnknownVersionMeetsMinimum(t *testing.T) {
	a := availSensor("edge", ago(5*time.Second), map[string]string{"trivy": ""})
	ta := findTool(t, ComputeToolAvailability([]CatalogTool{{Name: "trivy", Enabled: true, MinVersion: "0.55.0"}},
		[]SensorInventory{{Sensor: a}}, nil, testNow), "trivy")
	if ta.Status != ToolReady || ta.UpdateAvailable {
		t.Errorf("unknown version: status %s update %v, want ready false", ta.Status, ta.UpdateAvailable)
	}
}

func TestStateTakesJobs(t *testing.T) {
	for _, st := range AllStates() {
		want := st == StateOnline || st == StateDegraded || st == StateLate
		if st.TakesJobs() != want {
			t.Errorf("%s.TakesJobs() = %v, want %v", st, !want, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.4.2", "v3.4.10", -1},
		{"v1.0.0", "1.0", 0},
		{"1.0.0", "dev", 1},
		{"dev", "1.0.0", -1},
		{"alpha", "beta", -1},
		{"", "", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
