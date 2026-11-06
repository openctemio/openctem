package integration

// Names that stopped resolving reach their DNS re-check (resolve.dns, S5 of
// the coverage orchestrator). The live failure this reproduces: a coverage
// run of resolve.dns (dnsx) over names with no DNS answer, in a tenant with
// scan zones, was failed at claim with SCOPE_CHANGED, every target refused
// as "unresolved". A lookup-only job runs on such names (the dispatch gate
// and the claim re-check apply one rule); a job that probes its targets
// still does not, and ends as NO_RESOLVING_TARGETS, never SCOPE_CHANGED.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// officeZones is a tenant with one private scan zone and no default zone.
type officeZones struct{ zones []*scanzone.Zone }

func (z officeZones) List(context.Context, shared.ID) ([]*scanzone.Zone, error) { return z.zones, nil }

func (officeZones) RoutableSensors(context.Context, shared.ID, []shared.ID, string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	return map[shared.ID][]scanzone.SensorCandidate{}, nil
}

// noAnswerResolver: no name resolves.
type noAnswerResolver struct{}

func (noAnswerResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("no such host")
}

// ownedNoLimits is allOwned with no port- or path-limited scope entry, so
// the claim's port and path limit check (which every claim runs) passes.
type ownedNoLimits struct{ allOwned }

func (ownedNoLimits) ConstraintRefused(context.Context, shared.ID, []string, scopedom.Tier, scopedom.JobShape) (map[string]string, error) {
	return nil, nil
}

func seedPlainSensor(t *testing.T, db *sql.DB, tenant shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, reported_tool_names)
		 VALUES ($1, $2, $3, $4, 'pfx', 'active', '{dnsx,nuclei}')`,
		id.String(), tenant.String(), "lookup-"+id.String()[:8], "hash-"+id.String()); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	return id
}

func commandOfRun(t *testing.T, db *sql.DB, tenant, run shared.ID) shared.ID {
	t.Helper()
	var id string
	if err := db.QueryRowContext(context.Background(),
		`SELECT c.id FROM commands c JOIN scan_run_steps st ON st.id = c.scan_run_step_id
		 WHERE c.tenant_id = $1 AND st.scan_run_id = $2`, tenant.String(), run.String()).Scan(&id); err != nil {
		t.Fatalf("command of run: %v", err)
	}
	cid, _ := shared.IDFromString(id)
	return cid
}

func TestLookupOnlyJobsRunOnUnresolvedNames(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	sensor := seedPlainSensor(t, db, tenant)
	zone, err := scanzone.NewZone(tenant, "office", "", false, []string{"10.0.0.0/24"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	zone.SensorIDs = []shared.ID{sensor}
	pg := &postgres.DB{DB: db}
	svc := scansvc.NewService(
		postgres.NewScanRepository(pg), postgres.NewScanWorkflowRepository(pg), postgres.NewAssetGroupRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewScanWorkflowStepRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewCommandRepository(pg), nil, postgres.NewToolRepository(pg), availableSensors{}, nil,
		logger.New(logger.Config{Level: "error"}),
		allowAllTargetChecks(scansvc.WithScanZones(officeZones{zones: []*scanzone.Zone{zone}}, noAnswerResolver{}),
			scansvc.WithAttributionGate(ownedNoLimits{}))...,
	)
	commands := commandapp.NewService(postgres.NewCommandRepository(pg), logger.New(logger.Config{Level: "error"}),
		commandapp.WithScopeRecheck(svc))

	names := []string{"gone-a.example.com", "gone-b.example.com", "gone-c.example.com"}

	t.Run("resolve.dns coverage run is handed out", func(t *testing.T) {
		res, err := svc.StartCoverage(ctx, scansvc.CoverageInput{TenantID: tenant, Capability: "resolve.dns", Targets: names})
		if err != nil {
			t.Fatalf("start coverage: %v", err)
		}
		if res.RunID == nil || len(res.Kept) != len(names) || len(res.Refused) != 0 {
			t.Fatalf("coverage kept %v refused %v run %v", res.Kept, res.Refused, res.RunID)
		}
		id := commandOfRun(t, db, tenant, *res.RunID)
		got, err := commands.Acknowledge(ctx, tenant.String(), sensor.String(), id.String())
		if err != nil || got == nil {
			t.Fatalf("claim of the resolve.dns job: %v (the live failure was SCOPE_CHANGED, every name unresolved)", err)
		}
		var p struct {
			Targets []string `json:"targets"`
		}
		if json.Unmarshal(got.Payload, &p) != nil || len(p.Targets) != len(names) {
			t.Fatalf("handed out targets %v, want all %d", p.Targets, len(names))
		}
	})

	t.Run("a probing job on the same names ends as NO_RESOLVING_TARGETS", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": names})
		cmd, err := commanddom.NewCommand(tenant, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, payload)
		if err != nil {
			t.Fatal(err)
		}
		cmd.DispatchGate = &commanddom.DispatchGate{Tier: 1, ActScope: true, SystemPolicy: "coverage", Intensity: "active"}
		if err := postgres.NewCommandRepository(pg).Create(ctx, cmd); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := commands.Acknowledge(ctx, tenant.String(), sensor.String(), cmd.ID.String())
		if got != nil || !errors.Is(err, commandapp.ErrNoResolvingTargets) || errors.Is(err, commandapp.ErrScopeChanged) {
			t.Fatalf("claim of the nuclei job: %v %v, want ErrNoResolvingTargets", got, err)
		}
		var status, msg string
		if err := db.QueryRowContext(ctx, `SELECT status, COALESCE(error_message, '') FROM commands WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), cmd.ID.String()).Scan(&status, &msg); err != nil {
			t.Fatal(err)
		}
		if status != "failed" || !strings.HasPrefix(msg, "NO_RESOLVING_TARGETS: ") {
			t.Fatalf("stored %s %q", status, msg)
		}
	})
}
