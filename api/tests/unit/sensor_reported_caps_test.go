package unit

// Sensor-reported capabilities on the heartbeat (api RFC-029 §4.3.1): the
// service sanitizes the report against the tool catalog before it is
// written, and a heartbeat without a report leaves the stored one alone.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestUpdateHeartbeat_CapabilityReportIsSanitized(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.knownTools = map[string]bool{"nuclei": true, "semgrep": true}
	repo.knownCaps = map[string]bool{"sast": true}
	svc := newSensorSvcTestService(repo)
	a := repo.seedSensor(shared.NewID(), "s1", sensor.SensorTypeWorker)

	err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Report: &sensor.CapabilityReportInput{
			Tools: []sensor.ReportedTool{
				{Name: "nuclei", Version: "3.3.0", Installed: true},
				{Name: "not-in-catalog", Installed: true},
				{Name: "semgrep", Installed: false},
			},
			Capabilities:      []string{"sast", "validate:nuclei", "made-up"},
			MaxConcurrentJobs: 9999,
			OS:                "linux",
			Arch:              "arm64",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := repo.lastHeartbeat.Report
	if r == nil {
		t.Fatal("report not written")
	}
	wantTools := []sensor.ReportedTool{{Name: "nuclei", Version: "3.3.0", Installed: true}, {Name: "semgrep", Installed: false}}
	if !reflect.DeepEqual(r.Tools, wantTools) {
		t.Errorf("tools = %+v", r.Tools)
	}
	if !reflect.DeepEqual(r.Capabilities, []string{"sast", "validate:nuclei"}) {
		t.Errorf("capabilities = %v", r.Capabilities)
	}
	if r.MaxConcurrentJobs != sensor.MaxReportedJobs || r.OS != "linux" || r.Arch != "arm64" {
		t.Errorf("max/os/arch = %d/%s/%s", r.MaxConcurrentJobs, r.OS, r.Arch)
	}
}

func TestUpdateHeartbeat_NoReportLeavesStoredReport(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	a := repo.seedSensor(shared.NewID(), "s1", sensor.SensorTypeWorker)

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{Version: "1.0"}); err != nil {
		t.Fatal(err)
	}
	if repo.lastHeartbeat.Report != nil {
		t.Fatalf("an old SDK's heartbeat must not write a report: %+v", repo.lastHeartbeat.Report)
	}
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{Report: &sensor.CapabilityReportInput{}}); err != nil {
		t.Fatal(err)
	}
	if repo.lastHeartbeat.Report != nil {
		t.Fatalf("an empty report must not write: %+v", repo.lastHeartbeat.Report)
	}
}

// The catalog lookup failing must not fail the heartbeat (the sensor stays
// online), and nothing unchecked is written.
func TestUpdateHeartbeat_CatalogErrorSkipsReport(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.knownErr = errors.New("db down")
	svc := newSensorSvcTestService(repo)
	a := repo.seedSensor(shared.NewID(), "s1", sensor.SensorTypeWorker)

	err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Report: &sensor.CapabilityReportInput{Tools: []sensor.ReportedTool{{Name: "nuclei", Installed: true}}},
	})
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	if repo.lastHeartbeat.Report != nil {
		t.Fatalf("unchecked report written: %+v", repo.lastHeartbeat.Report)
	}
	if repo.updateHeartbeatCalls != 1 {
		t.Fatalf("heartbeat not written")
	}
}

// Only concurrency and platform reported: no catalog lookup is needed and
// the lists stay "not reported".
func TestUpdateHeartbeat_ReportWithoutLists(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.knownErr = errors.New("must not be called")
	svc := newSensorSvcTestService(repo)
	a := repo.seedSensor(shared.NewID(), "s1", sensor.SensorTypeWorker)

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Report: &sensor.CapabilityReportInput{MaxConcurrentJobs: 3, OS: "linux"},
	}); err != nil {
		t.Fatal(err)
	}
	r := repo.lastHeartbeat.Report
	if r == nil || r.MaxConcurrentJobs != 3 || r.OS != "linux" || r.Tools != nil || r.Capabilities != nil {
		t.Fatalf("report = %+v", r)
	}
}

// Tools and capabilities on a sensor are limits: a present list replaces
// the limit, [] removes it, an absent list leaves it.
func TestUpdateSensor_ToolLimits(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "s1", sensor.SensorTypeWorker)
	a.Tools = []string{"nuclei"}
	a.Capabilities = []string{"nuclei"}

	upd := func(tools, caps []string) *sensor.Sensor {
		t.Helper()
		out, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
			TenantID: tenantID.String(), SensorID: a.ID.String(), Tools: tools, Capabilities: caps,
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := upd(nil, nil); !reflect.DeepEqual(got.Tools, []string{"nuclei"}) {
		t.Fatalf("absent list changed tools: %v", got.Tools)
	}
	if got := upd([]string{"semgrep", "nuclei"}, []string{"semgrep"}); !reflect.DeepEqual(got.Tools, []string{"semgrep", "nuclei"}) || !reflect.DeepEqual(got.Capabilities, []string{"semgrep"}) {
		t.Fatalf("list did not replace: %v %v", got.Tools, got.Capabilities)
	}
	if got := upd([]string{}, []string{}); len(got.Tools) != 0 || got.Tools == nil || len(got.Capabilities) != 0 {
		t.Fatalf("[] did not clear the limit: %#v %#v", got.Tools, got.Capabilities)
	}
}

func TestCreateSensor_ToolLimitsAreCanonical(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: shared.NewID().String(), Name: "s", Type: "worker",
		Tools: []string{" Nuclei ", "gitleaks", "nuclei"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Sensor.Tools, []string{"nuclei", "betterleaks"}) {
		t.Fatalf("tools = %v", out.Sensor.Tools)
	}
}
