package postgres

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// isolationFixtureTool is a placeholder tool that needs strong isolation in
// these tests only; production wires no such tool.
const isolationFixtureTool = "isolation-fixture"

// A job of a tool that needs strong isolation is stamped with the feature at
// creation, is returned by the poll only to a sensor that itself reported
// isolation.strong@1 (never to one that only declared it, nor one that did
// not), and the placement explainer names the wait reason. A job of another
// tool is not stamped and is not held. Against the real claim SQL.
func TestStrongIsolationJobGoesOnlyToAProvenSensor(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	repo := NewCommandRepository(pg)
	repo.SetStrongIsolationTools(func(tool string) bool { return tool == isolationFixtureTool })
	sensRep := NewSensorRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)

	tools := zoneSensorOpts{tools: []string{isolationFixtureTool, "nuclei"}}
	strong := seedZoneSensor(ctx, t, sqlDB, &tenant, "a-strong", tools)
	declared := seedZoneSensor(ctx, t, sqlDB, &tenant, "b-declared-strong", tools)
	plain := seedZoneSensor(ctx, t, sqlDB, &tenant, "c-process-only", tools)
	for q, id := range map[string]shared.ID{
		`UPDATE sensors SET reported_capabilities = '{isolation-fixture,nuclei,isolation.strong@1}' WHERE id = $1`: strong,
		`UPDATE sensors SET capabilities = '{isolation-fixture,nuclei,isolation.strong@1}' WHERE id = $1`:          declared,
	} {
		if _, err := sqlDB.ExecContext(ctx, q, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	needs := createPayloadCommand(ctx, t, repo, tenant, nil, map[string]any{"scanner": isolationFixtureTool, "targets": []string{"203.0.113.7"}})
	other := createPayloadCommand(ctx, t, repo, tenant, nil, map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.7"}})

	var payload []byte
	if err := sqlDB.QueryRowContext(ctx, `SELECT payload FROM commands WHERE id = $1`, needs.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Features []string `json:"required_features"`
	}
	_ = json.Unmarshal(payload, &p)
	if !slices.Equal(p.Features, []string{sensor.CapabilityIsolationStrong}) {
		t.Fatalf("a strong-isolation job carries the feature, got %v", p.Features)
	}
	if err := sqlDB.QueryRowContext(ctx, `SELECT payload FROM commands WHERE id = $1`, other.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var q struct {
		Features []string `json:"required_features"`
	}
	_ = json.Unmarshal(payload, &q)
	if len(q.Features) != 0 {
		t.Fatalf("a process-isolation job is not stamped: %v", q.Features)
	}

	svc := commandapp.NewService(repo, logger.NewNop(), commandapp.WithSensorLookup(sensRep))
	polled := func(id, cmd shared.ID) bool {
		sn, err := sensRep.GetByTenantAndID(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		got, err := svc.Poll(ctx, commandapp.PollInput{TenantID: tenant.String(), SensorID: id.String(),
			Capabilities: sn.EffectiveCapabilities(), Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(got, func(c *command.Command) bool { return c.ID == cmd })
	}
	for name, c := range map[string]struct {
		id   shared.ID
		want bool
	}{"proven strong sensor": {strong, true}, "declared only": {declared, false}, "process only": {plain, false}} {
		if got := polled(c.id, needs); got != c.want {
			t.Errorf("%s: poll returns the strong-isolation job %v, want %v", name, got, c.want)
		}
	}
	if !polled(plain, other) {
		t.Error("a process-isolation job is not held back")
	}

	pl, err := svc.ExplainPlacement(ctx, tenant, needs)
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range pl.Sensors {
		switch sp.SensorID {
		case strong:
			if !sp.Eligible {
				t.Errorf("the proven sensor is eligible: %v", sp.Reasons)
			}
		default:
			if sp.Eligible || !slices.Contains(sp.Reasons, command.PlacementStrongIsolationMissing) {
				t.Errorf("%s: eligible %v reasons %v, want %s", sp.Name, sp.Eligible, sp.Reasons, command.PlacementStrongIsolationMissing)
			}
		}
	}
}
