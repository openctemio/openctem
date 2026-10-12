package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func scanCfg(intg *integration.Integration, extra map[string]any) map[string]any {
	c := map[string]any{"integration_id": intg.ID().String(), "policy_id": float64(1000003), "repository_id": float64(5)}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestParseScanConfig(t *testing.T) {
	id := shared.NewID().String()
	ok, err := ParseScanConfig(map[string]any{"integration_id": id, "policy_id": "7", "repository_id": float64(5)})
	if err != nil || ok.PolicyID != 7 || ok.MaxScanSeconds != DefaultMaxScanSeconds || ok.ZoneID != 0 {
		t.Fatalf("%+v %v", ok, err)
	}
	for name, c := range map[string]map[string]any{
		"no integration":   {"policy_id": float64(1), "repository_id": float64(1)},
		"no policy":        {"integration_id": id, "repository_id": float64(1)},
		"zero repository":  {"integration_id": id, "policy_id": float64(1), "repository_id": float64(0)},
		"negative zone":    {"integration_id": id, "policy_id": float64(1), "repository_id": float64(1), "zone_id": float64(-1)},
		"too short":        {"integration_id": id, "policy_id": float64(1), "repository_id": float64(1), "max_scan_seconds": float64(5)},
		"too long":         {"integration_id": id, "policy_id": float64(1), "repository_id": float64(1), "max_scan_seconds": float64(MaxMaxScanSeconds + 1)},
		"fractional id":    {"integration_id": id, "policy_id": 1.5, "repository_id": float64(1)},
		"policy as object": {"integration_id": id, "policy_id": map[string]any{}, "repository_id": float64(1)},
	} {
		if _, err := ParseScanConfig(c); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func withCatalog(intg *integration.Integration, c *Catalog) {
	st := readState(intg)
	st.Catalog = c
	writeState(intg, st)
}

func TestNewScanCommand(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	bk := map[string]string{"run_id": "r1", "scan_id": "s1", "scan_run_id": "r1", "step_key": "scan", "scan_run_step_id": "sr1"}

	cmd, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, map[string]any{"zone_id": float64(2), "max_scan_seconds": float64(3600)}),
		[]string{"10.0.0.0/28", "10.0.1.5"}, bk)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Type != command.CommandTypeConnectorScan || cmd.SensorID == nil || *cmd.SensorID != e.sensorID || cmd.TenantID != e.tenant {
		t.Fatalf("command %+v", cmd)
	}
	if want := e.now.Add(time.Hour + scanImportGrace); cmd.ExpiresAt == nil || !cmd.ExpiresAt.Equal(want) {
		t.Fatalf("expiry %v, want %v", cmd.ExpiresAt, want)
	}
	// The claim re-checks the targets: full gate at t1, outside every zone.
	if g := cmd.DispatchGate; g == nil || *g != (command.DispatchGate{Tier: 1, Validated: true, NoZoneRouting: true}) {
		t.Fatalf("dispatch gate %+v", g)
	}
	var p ScanPayload
	_ = json.Unmarshal(cmd.Payload, &p)
	if p.Scanner != ToolName || p.ZoneID != 2 || p.MaxScanSeconds != 3600 || len(p.Targets) != 2 ||
		p.StepRunID != "sr1" || p.Instance != "sc-prod" || p.MinSeverity != 1 {
		t.Fatalf("payload %+v", p)
	}

	// Catalog checks, when the sensor reported one.
	withCatalog(e.intg, &Catalog{Policies: []CatalogItem{{ID: 1000003}}, ScanRepositories: []CatalogItem{{ID: 5}}, ScanZones: []CatalogItem{{ID: 3}}})
	if _, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, map[string]any{"zone_id": float64(2)}), []string{"10.0.0.1"}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zone outside the catalog: %v", err)
	}
	if _, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, map[string]any{"policy_id": float64(9)}), []string{"10.0.0.1"}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("policy outside the catalog: %v", err)
	}
	if _, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, nil), []string{"10.0.0.1"}, nil); err != nil {
		t.Fatalf("inside the catalog: %v", err)
	}

	// Refusals.
	if _, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, nil), nil, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no targets: %v", err)
	}
	if _, err := e.svc.NewScanCommand(ctx, shared.NewID(), scanCfg(e.intg, nil), []string{"10.0.0.1"}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("another tenant's integration: %v", err)
	}
	e.sensors.rows[e.sensorID].Status = "disabled"
	if _, err := e.svc.NewScanCommand(ctx, e.tenant, scanCfg(e.intg, nil), []string{"10.0.0.1"}, nil); !errors.Is(err, ErrSensorUnavailable) {
		t.Fatalf("inactive sensor: %v", err)
	}
}

func TestParseCatalog(t *testing.T) {
	c := parseCatalog(map[string]any{
		"policies": []any{
			map[string]any{"id": float64(1), "name": "ok"},
			map[string]any{"id": float64(-1), "name": "bad id"},
			map[string]any{"id": "x"},
			"junk",
		},
	})
	if c == nil || len(c.Policies) != 1 || c.Policies[0].ID != 1 {
		t.Fatalf("%+v", c)
	}
	if parseCatalog("nope") != nil || parseCatalog(map[string]any{}) != nil {
		t.Fatal("garbage must yield no catalog")
	}
}
