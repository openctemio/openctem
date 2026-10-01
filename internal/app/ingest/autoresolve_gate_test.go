package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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
	stored := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Tools: []string{"gitleaks"}}
	svc := gateService(stored)
	jobSensor := &sensor.Sensor{ID: stored.ID, TenantID: &tid, Status: sensor.SensorStatusActive}

	if svc.sensorMayAutoResolveTool(context.Background(), jobSensor, "semgrep") {
		t.Fatal("async-ingested report for an undeclared tool must not auto-resolve")
	}
	if !svc.sensorMayAutoResolveTool(context.Background(), jobSensor, "gitleaks") {
		t.Fatal("async-ingested report for a declared tool must auto-resolve")
	}
}
