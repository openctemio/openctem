package postgres

// The effective_* generated columns (migration 000253) must compute the same
// narrowing rule as Sensor.Effective* (pkg/domain/sensor/reported.go): the
// dispatch queries read the columns, the poll and the API read the methods.

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSensorEffectiveColumnsMatchDomain(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	repo := NewSensorRepository(&DB{DB: db})

	lists := [][]string{nil, {}, {"nuclei"}, {"nuclei", "semgrep"}, {"semgrep", "trivy"}}
	maxes := []int{0, 1, 5, 50}
	slots := []int{0, 3, 64} // capacity.slots_total; 0: no load report
	n := 0
	for _, declared := range lists[1:] { // declared is NOT NULL (default '{}')
		for _, reported := range lists {
			for i, rmax := range maxes {
				slot := slots[(n+i)%len(slots)]
				n++
				a, err := sensor.NewSensor(tenantID, fmt.Sprintf("parity-%d", n), sensor.SensorTypeWorker, "", declared, sensor.ExecutionModeDaemon)
				if err != nil {
					t.Fatal(err)
				}
				a.SetAPIKey(fmt.Sprintf("hash-%s", a.ID), "rda_x")
				if err := repo.Create(ctx, a); err != nil {
					t.Fatal(err)
				}
				var tools []sensor.ReportedTool
				if reported != nil {
					tools = []sensor.ReportedTool{}
					for _, r := range reported {
						tools = append(tools, sensor.ReportedTool{Name: r, Installed: true})
					}
					tools = append(tools, sensor.ReportedTool{Name: "zap", Installed: false})
				}
				rep := &sensor.CapabilityReport{Tools: tools, Capabilities: reported, MaxConcurrentJobs: rmax}
				if !rep.HasReport() {
					rep = nil
				}
				var load *sensor.LoadReport
				if slot > 0 {
					load = &sensor.LoadReport{Capacity: &sensor.ReportedCapacity{SlotsTotal: slot, SlotsFree: slot}}
				}
				if ok, err := repo.UpdateHeartbeat(ctx, a.ID, sensor.HeartbeatUpdate{TenantID: &tenantID, Report: rep, Load: load}); err != nil || !ok {
					t.Fatalf("heartbeat: %v %v", ok, err)
				}
				got, err := repo.GetByID(ctx, a.ID)
				if err != nil {
					t.Fatal(err)
				}
				var dbTools, dbCaps pq.StringArray
				var dbMax int
				if err := db.QueryRowContext(ctx,
					`SELECT effective_tools, effective_capabilities, effective_max_jobs FROM sensors WHERE id = $1`,
					a.ID.String()).Scan(&dbTools, &dbCaps, &dbMax); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("declared=%v reported=%v max=%d slots=%d", declared, reported, rmax, slot)
				if !slices.Equal([]string(dbTools), got.EffectiveTools()) {
					t.Errorf("%s: tools db=%v domain=%v", name, dbTools, got.EffectiveTools())
				}
				if !slices.Equal([]string(dbCaps), got.EffectiveCapabilities()) {
					t.Errorf("%s: caps db=%v domain=%v", name, dbCaps, got.EffectiveCapabilities())
				}
				if dbMax != got.EffectiveMaxConcurrentJobs() {
					t.Errorf("%s: max db=%d domain=%d", name, dbMax, got.EffectiveMaxConcurrentJobs())
				}
			}
		}
	}
}

func TestKnownCapabilityNames_TenantScoped(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	mine := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	repo := NewSensorRepository(&DB{DB: db})

	for _, tc := range []struct {
		tenant shared.ID
		name   string
	}{{mine, "mytool"}, {other, "theirtool"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tools (tenant_id, name, display_name, is_active, is_builtin) VALUES ($1, $2, $2, TRUE, FALSE)`,
			tc.tenant.String(), tc.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tools (tenant_id, name, display_name, is_active, is_builtin) VALUES ($1, 'mydisabled', 'x', FALSE, FALSE)`, mine.String()); err != nil {
		t.Fatal(err)
	}

	tools, caps, err := repo.KnownCapabilityNames(ctx, &mine,
		[]string{"nuclei", "mytool", "theirtool", "mydisabled", "nope"}, []string{"sast", "nope", "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	if !tools["nuclei"] || !tools["mytool"] || tools["theirtool"] || tools["mydisabled"] || tools["nope"] {
		t.Fatalf("known tools %v", tools)
	}
	if !caps["sast"] || caps["nope"] {
		t.Fatalf("known capabilities %v", caps)
	}

	// A platform sensor (no tenant) knows only the platform's tools.
	tools, _, err = repo.KnownCapabilityNames(ctx, nil, []string{"nuclei", "mytool"}, nil)
	if err != nil || !tools["nuclei"] || tools["mytool"] {
		t.Fatalf("platform: %v %v", tools, err)
	}
}

// Zone routing uses the effective tools and capacity, and a report never
// widens zone membership.
func TestRoutableSensors_UseReportedTools(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	zones := NewScanZoneRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	z := newTestZone(t, tenant, "dc", false, "10.0.0.0/8")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	report := func(id shared.ID, toolsJSON string, names []string) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET reported_tools = $2::jsonb, reported_tool_names = $3, reported_at = NOW() WHERE id = $1`,
			id.String(), toolsJSON, pq.Array(names)); err != nil {
			t.Fatal(err)
		}
	}
	reportsNuclei := seedZoneSensor(ctx, t, sqlDB, &tenant, "reports-nuclei", zoneSensorOpts{tools: []string{}})
	report(reportsNuclei, `[{"name":"nuclei","installed":true}]`, []string{"nuclei"})
	declaredMissing := seedZoneSensor(ctx, t, sqlDB, &tenant, "declared-missing", zoneSensorOpts{tools: []string{"nuclei"}})
	report(declaredMissing, `[{"name":"nuclei","installed":false}]`, []string{})
	outside := seedZoneSensor(ctx, t, sqlDB, &tenant, "outside-zone", zoneSensorOpts{tools: []string{}})
	report(outside, `[{"name":"nuclei","installed":true}]`, []string{"nuclei"})
	for _, s := range []shared.ID{reportsNuclei, declaredMissing} {
		if err := zones.AssignSensor(ctx, tenant, z.ID, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	got, err := zones.RoutableSensors(ctx, tenant, []shared.ID{z.ID}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if list := got[z.ID]; len(list) != 1 || list[0].ID != reportsNuclei {
		t.Fatalf("routable = %+v; want only the in-zone sensor that reports nuclei", list)
	}
}

// The live case behind RFC-033: a 4-core sensor reported the SDK's upper
// bound (64) as its ceiling and 4 slots; the administrator's limit is 5.
// Dispatch capacity is the 4 it can run, in the column and in the domain,
// and the per-tool kind and capabilities of its report are kept.
func TestEffectiveMaxJobs_BoundedBySlots(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	repo := NewSensorRepository(&DB{DB: db})

	for _, tc := range []struct {
		name                  string
		admin, ceiling, slots int
		want                  int
	}{
		{"live: ceiling 64, slots 4, admin 5", 5, 64, 4, 4},
		{"no ceiling reported", 5, 0, 4, 4},
		{"slots above the admin limit", 5, 0, 8, 5},
		{"operator ceiling below the slots", 10, 2, 4, 2},
		{"no load report: as before", 5, 64, 0, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := sensor.NewSensor(tenantID, "slots-"+shared.NewID().String()[:8], sensor.SensorTypeWorker, "", []string{}, sensor.ExecutionModeDaemon)
			if err != nil {
				t.Fatal(err)
			}
			a.SetAPIKey("hash-"+a.ID.String(), "rda_x")
			a.SetMaxConcurrentJobs(tc.admin)
			if err := repo.Create(ctx, a); err != nil {
				t.Fatal(err)
			}
			rep := &sensor.CapabilityReport{
				Tools: []sensor.ReportedTool{{Name: "nuclei", Kind: sensor.ToolKindScanner, Version: "v3.11.1", Installed: true,
					Capabilities: []string{"dast", "validate:nuclei"}}},
				Capabilities:      []string{"nuclei", "dast", "validate:nuclei"},
				MaxConcurrentJobs: tc.ceiling,
			}
			var load *sensor.LoadReport
			if tc.slots > 0 {
				load = &sensor.LoadReport{Capacity: &sensor.ReportedCapacity{SlotsTotal: tc.slots, SlotsFree: tc.slots}}
			}
			if ok, err := repo.UpdateHeartbeat(ctx, a.ID, sensor.HeartbeatUpdate{TenantID: &tenantID, Report: rep, Load: load}); err != nil || !ok {
				t.Fatalf("heartbeat: %v %v", ok, err)
			}
			var dbMax int
			if err := db.QueryRowContext(ctx, `SELECT effective_max_jobs FROM sensors WHERE id = $1`, a.ID.String()).Scan(&dbMax); err != nil {
				t.Fatal(err)
			}
			got, err := repo.GetByID(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if dbMax != tc.want || got.EffectiveMaxConcurrentJobs() != tc.want {
				t.Fatalf("effective max jobs: db=%d domain=%d, want %d", dbMax, got.EffectiveMaxConcurrentJobs(), tc.want)
			}
			tools := got.Reported.Tools
			if len(tools) != 1 || tools[0].Kind != sensor.ToolKindScanner || !slices.Equal(tools[0].Capabilities, []string{"dast", "validate:nuclei"}) {
				t.Fatalf("reported tools = %+v", tools)
			}
		})
	}
}
