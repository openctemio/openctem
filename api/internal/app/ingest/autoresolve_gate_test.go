package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sensorRowRepo serves only GetByID (the gate's lookup for async-ingest sensors);
// any other call panics via the nil embedded interface.
type sensorRowRepo struct {
	sensor.Repository
	rows map[shared.ID]*sensor.Sensor
}

func (r *sensorRowRepo) GetByID(_ context.Context, id shared.ID) (*sensor.Sensor, error) {
	if a, ok := r.rows[id]; ok {
		return a, nil
	}
	return nil, shared.ErrNotFound
}

func gateService(rows ...*sensor.Sensor) *Service {
	repo := &sensorRowRepo{rows: map[shared.ID]*sensor.Sensor{}}
	for _, a := range rows {
		repo.rows[a.ID] = a
	}
	return &Service{logger: logger.NewNop(), sensorRepo: repo}
}

func TestSensorMayAutoResolveTool(t *testing.T) {
	tid := shared.NewID()
	declared := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Tools: []string{"semgrep", "Trivy"}}
	legacy := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid}
	svc := gateService(declared)

	cases := []struct {
		name string
		agt  *sensor.Sensor
		tool string
		want bool
	}{
		// Legit flows keep working.
		{"declared tool", declared, "semgrep", true},
		{"declared tool, case-insensitive", declared, "trivy", true},
		{"legacy sensor without declared tools (backward compat)", legacy, "nuclei", true},
		{"server-side synthetic ingest", &sensor.Sensor{TenantID: &tid}, "tenable", true},
		{"server-side synthetic ingest, defectdojo", &sensor.Sensor{TenantID: &tid}, "defectdojo", true},

		// Attacks: a sensor claiming another tool's name.
		{"tool not declared by the sensor", declared, "nuclei", false},
		{"reserved tool name from declared sensor", declared, "defectdojo", false},
		{"reserved tool name from legacy sensor", legacy, "pentest-manual", false},
		{"reserved tool name, case/space variant", legacy, " Burp_Suite ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := svc.sensorMayAutoResolveTool(context.Background(), tc.agt, tc.tool); got != tc.want {
				t.Fatalf("sensorMayAutoResolveTool(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}

// The async ingest worker rebuilds the sensor from the job with only ID +
// tenant; the gate must load the declared tools from the sensor row instead of
// treating it as a legacy (unrestricted) sensor.
func TestSensorMayAutoResolveTool_AsyncJobSensorLoadsDeclaredTools(t *testing.T) {
	tid := shared.NewID()
	stored := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Tools: []string{"betterleaks"}}
	svc := gateService(stored)
	jobSensor := &sensor.Sensor{ID: stored.ID, TenantID: &tid, Status: sensor.SensorStatusActive}

	if svc.sensorMayAutoResolveTool(context.Background(), jobSensor, "semgrep") {
		t.Fatal("async-ingested report for an undeclared tool must not auto-resolve")
	}
	if !svc.sensorMayAutoResolveTool(context.Background(), jobSensor, "betterleaks") {
		t.Fatal("async-ingested report for a declared tool must auto-resolve")
	}
}

// A sensor whose admin-assigned tools still say "gitleaks" (or an old sensor
// reporting "gitleaks") and a report Ingest has mapped to "betterleaks" name
// the same tool: auto-resolve and the v2 tool check must not reject it.
func TestSensorToolChecksMatchAcrossTheGitleaksRename(t *testing.T) {
	tid := shared.NewID()
	old := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Tools: []string{"gitleaks"}}
	svc := gateService(old)
	if !svc.sensorMayAutoResolveTool(context.Background(), old, "betterleaks") {
		t.Fatal("sensor declaring gitleaks must auto-resolve its betterleaks-mapped report")
	}
	if !SensorDeclaresTool([]string{"gitleaks"}, "betterleaks") || !SensorDeclaresTool([]string{"betterleaks"}, "gitleaks") {
		t.Fatal("SensorDeclaresTool must treat gitleaks and betterleaks as one tool")
	}
	if SensorDeclaresTool([]string{"gitleaks"}, "semgrep") {
		t.Fatal("the rename must not widen what a sensor may report")
	}
}

// A sensor that reports its inventory may auto-resolve its effective tools
// (reported installed ∩ its limit), and an empty report is not the legacy
// "no tools declared" case.
func TestSensorMayAutoResolveTool_ReportedTools(t *testing.T) {
	tid := shared.NewID()
	reports := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid,
		Reported: sensor.CapabilityReport{Tools: []sensor.ReportedTool{{Name: "nuclei", Installed: true}}}}
	none := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid,
		Reported: sensor.CapabilityReport{Tools: []sensor.ReportedTool{}}}
	missing := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Tools: []string{"semgrep"},
		Reported: sensor.CapabilityReport{Tools: []sensor.ReportedTool{{Name: "semgrep", Installed: false}}}}
	svc := gateService(reports, none, missing)
	ctx := context.Background()
	if !svc.sensorMayAutoResolveTool(ctx, reports, "nuclei") {
		t.Error("a reported, installed tool must auto-resolve")
	}
	if svc.sensorMayAutoResolveTool(ctx, reports, "semgrep") {
		t.Error("a tool the sensor does not report must not auto-resolve")
	}
	if svc.sensorMayAutoResolveTool(ctx, none, "nuclei") {
		t.Error("a sensor that reports nothing installed is not a legacy sensor")
	}
	if svc.sensorMayAutoResolveTool(ctx, missing, "semgrep") {
		t.Error("a declared tool the sensor reports missing must not auto-resolve")
	}
	// The async worker's minimal sensor loads the stored report.
	if !svc.sensorMayAutoResolveTool(ctx, &sensor.Sensor{ID: reports.ID, TenantID: &tid}, "nuclei") {
		t.Error("async-ingested report: stored report not used")
	}
	if svc.sensorMayAutoResolveTool(ctx, &sensor.Sensor{ID: none.ID, TenantID: &tid}, "nuclei") {
		t.Error("async-ingested report: empty stored report treated as legacy")
	}
	if !SensorDeclaresTool(reports.EffectiveTools(), "nuclei") || SensorDeclaresTool(missing.EffectiveTools(), "semgrep") {
		t.Error("v2 results tool check does not follow the effective tools")
	}
}
