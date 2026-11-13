package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	commandapp "github.com/openctemio/openctem/server/internal/app/command"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Port scans that name no ports, on sensors whose local policy lists
// ports.allow (docs/architecture/sensor-local-policy.md, "Port scans"): the
// job a sensor gets carries the ports its policy allows; a job whose ports
// the policy allows none of is not sent, and fails with PORTS_NOT_ALLOWED
// when no other sensor may run it.

func portScanPayload(target string) map[string]any {
	return map[string]any{"scanner": "naabu", "capability": "scan.ports@1", "targets": []string{target},
		"config": map[string]any{"top_ports": "100"}}
}

func TestPortScan_PortsFilledFromThePolicy(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(pg)
	sensors := NewSensorRepository(pg)
	cmds := NewCommandRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)

	zone := newTestZone(t, tenant, "edge", false, "10.41.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "ports", zoneSensorOpts{tools: []string{"naabu"}})
	if err := zones.AssignSensor(ctx, tenant, zone.ID, s, nil); err != nil {
		t.Fatal(err)
	}
	setLocalPolicy(ctx, t, sensors, tenant, s, &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true, Ports: "22,443,60000"}})
	id := createPayloadCommand(ctx, t, cmds, tenant, &zone.ID, portScanPayload("10.41.0.5"))

	svc := commandapp.NewService(cmds, logger.NewNop(), commandapp.WithSensorLookup(sensors))
	got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: s.String(), Limit: 10, MaxJobs: 5})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(got) != 1 || got[0].ID != id {
		t.Fatalf("claimed %d commands, want the port scan", len(got))
	}
	var p struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(got[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Config["ports"] != "22,443" || p.Config["top_ports"] != nil {
		t.Fatalf("delivered config %v, want ports 22,443 and no top_ports", p.Config)
	}
	// The stored command is unchanged: the fill is per sensor.
	stored, _ := cmds.GetByTenantAndID(ctx, tenant, id)
	if strings.Contains(string(stored.Payload), `"ports":"22,443"`) {
		t.Fatalf("stored payload changed: %s", stored.Payload)
	}
}

func TestPortScan_NoAllowedPortIsNotSent(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(pg)
	sensors := NewSensorRepository(pg)
	cmds := NewCommandRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)

	zone := newTestZone(t, tenant, "core", false, "10.42.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	strict := seedZoneSensor(ctx, t, sqlDB, &tenant, "strict", zoneSensorOpts{tools: []string{"naabu"}})
	other := seedZoneSensor(ctx, t, sqlDB, &tenant, "other", zoneSensorOpts{tools: []string{"naabu"}})
	for _, id := range []shared.ID{strict, other} {
		if err := zones.AssignSensor(ctx, tenant, zone.ID, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	none := &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true, Ports: "60000-60010"}}
	setLocalPolicy(ctx, t, sensors, tenant, strict, none)
	setLocalPolicy(ctx, t, sensors, tenant, other, &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true, Ports: "80"}})

	svc := commandapp.NewService(cmds, logger.NewNop(), commandapp.WithSensorLookup(sensors))
	claim := func(id shared.ID) int {
		t.Helper()
		got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: id.String(), Limit: 10, MaxJobs: 5})
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		return len(got)
	}

	// Another sensor allows port 80: the job waits for it.
	waits := createPayloadCommand(ctx, t, cmds, tenant, &zone.ID, portScanPayload("10.42.0.5"))
	if n := claim(strict); n != 0 {
		t.Fatalf("strict sensor claimed %d commands", n)
	}
	if c, _ := cmds.GetByTenantAndID(ctx, tenant, waits); c.Status != command.CommandStatusPending {
		t.Fatalf("job with another able sensor is %s, want pending", c.Status)
	}
	if n := claim(other); n != 1 {
		t.Fatalf("other sensor claimed %d commands, want 1", n)
	}

	// No sensor allows any of its ports: it fails with PORTS_NOT_ALLOWED.
	setLocalPolicy(ctx, t, sensors, tenant, other, none)
	refused := createPayloadCommand(ctx, t, cmds, tenant, &zone.ID, portScanPayload("10.42.0.6"))
	if n := claim(strict); n != 0 {
		t.Fatalf("strict sensor claimed %d commands", n)
	}
	c, _ := cmds.GetByTenantAndID(ctx, tenant, refused)
	if c.Status != command.CommandStatusFailed || !strings.HasPrefix(c.ErrorMessage, commandapp.FailurePortsNotAllowed+":") {
		t.Fatalf("job is %s %q, want failed with %s", c.Status, c.ErrorMessage, commandapp.FailurePortsNotAllowed)
	}
}
