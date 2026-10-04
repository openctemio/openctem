package integration

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A scan whose scanner is tenable_sc (RFC-047 §5.2) on a migrated database:
// its config must name the tenant's own connector and a policy and repository
// the sensor allows; a run sends one connector_scan command, pinned to the
// connector's sensor, with only the targets the owner may scan.
func TestTenableSCConnectorScan(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenant, other := seedLifecycleTenant(ctx, t, db), seedLifecycleTenant(ctx, t, db)
	member, admin := seedActUser(t, db), seedActUser(t, db)
	mine := seedActAsset(t, db, tenant, "mine.example.com")
	seedActAsset(t, db, tenant, "theirs.example.com")
	grantScope(t, db, tenant, member, mine)

	sensorID := seedReportingSensor(t, db, tenant, tenablesc.ToolName)
	otherSensor := seedReportingSensor(t, db, other, tenablesc.ToolName)

	intRepo := postgres.NewIntegrationRepository(pg)
	newConnector := func(tn, sn shared.ID) *integration.Integration {
		i := integration.NewIntegration(shared.NewID(), tn, "sc-"+shared.NewID().String()[:6], integration.CategorySecurity,
			integration.ProviderTenable, integration.AuthTypeAPIKey)
		i.SetConfig(map[string]any{"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": sn.String(), "instance": "sc-prod"})
		i.SetMetadata(map[string]any{"tenable_sync": map[string]any{"catalog": map[string]any{
			"policies":          []any{map[string]any{"id": 1000003, "name": "Basic Network Scan"}},
			"scan_repositories": []any{map[string]any{"id": 5, "name": "Datacenter"}},
		}}})
		if err := intRepo.Create(ctx, i); err != nil {
			t.Fatalf("create integration: %v", err)
		}
		return i
	}
	conn := newConnector(tenant, sensorID)
	foreignConn := newConnector(other, otherSensor)

	connector := tenablesc.NewService(intRepo, postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg),
		postgres.NewFindingRepository(pg), nil, logger.NewNop())
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithActScope(actScopeChecker(db, admin)), scansvc.WithConnectorScans(connector))
	asAdmin := asCaller(ctx, datascope.Caller{UserID: admin.String(), IsAdmin: true})

	cfg := func(intg *integration.Integration, policy, repo int) map[string]any {
		return map[string]any{"integration_id": intg.ID().String(), "policy_id": float64(policy), "repository_id": float64(repo)}
	}
	create := func(scannerCfg map[string]any, owner shared.ID, targets ...string) (shared.ID, error) {
		sc, err := svc.CreateScan(asAdmin, scansvc.CreateScanInput{
			TenantID: tenant.String(), Name: "tsc " + shared.NewID().String(), ScanType: "single",
			ScannerName: tenablesc.ToolName, ScannerConfig: scannerCfg, Targets: targets, CreatedBy: owner.String(),
		})
		if err != nil {
			return shared.ID{}, err
		}
		return sc.ID, nil
	}

	t.Run("config refusals", func(t *testing.T) {
		for name, c := range map[string]map[string]any{
			"policy not allowed by the sensor":     cfg(conn, 42, 5),
			"repository not allowed by the sensor": cfg(conn, 1000003, 9),
			"another tenant's connector":           cfg(foreignConn, 1000003, 5),
			"no integration":                       {"policy_id": float64(1000003), "repository_id": float64(5)},
		} {
			if _, err := create(c, admin, "mine.example.com"); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s: err = %v, want a validation error", name, err)
			}
		}
	})

	t.Run("a run queues one pinned connector_scan with the owner's targets", func(t *testing.T) {
		id, err := create(cfg(conn, 1000003, 5), member, "mine.example.com", "theirs.example.com")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenant.String(), ScanID: id.String()})
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		var (
			typ     string
			pinned  string
			payload []byte
		)
		if err := db.QueryRowContext(ctx, `SELECT type, sensor_id::text, payload FROM commands
			WHERE tenant_id = $1 AND payload->>'run_id' = $2`, tenant.String(), run.ID.String()).Scan(&typ, &pinned, &payload); err != nil {
			t.Fatalf("read command: %v", err)
		}
		if typ != "connector_scan" || pinned != sensorID.String() {
			t.Fatalf("type %q sensor %q", typ, pinned)
		}
		var p tenablesc.ScanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.Scanner != tenablesc.ToolName || p.PolicyID != 1000003 || p.RepositoryID != 5 || p.Instance != "sc-prod" ||
			p.PipelineRunID != run.ID.String() || p.StepRunID == "" {
			t.Fatalf("payload %+v", p)
		}
		if !slices.Equal(p.Targets, []string{"mine.example.com"}) {
			t.Fatalf("targets %v, want only the owner's asset", p.Targets)
		}
		var raw map[string]any
		_ = json.Unmarshal(payload, &raw)
		for _, k := range []string{"url", "base_url", "access_key", "secret_key"} {
			if _, ok := raw[k]; ok {
				t.Fatalf("payload carries %q", k)
			}
		}
	})

	t.Run("a sensor that stopped running the connector refuses the run", func(t *testing.T) {
		id, err := create(cfg(conn, 1000003, 5), admin, "mine.example.com")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE sensors SET reported_tools = '[{"name":"nuclei","installed":true}]',
			reported_tool_names = ARRAY['nuclei'] WHERE id = $1`, sensorID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenant.String(), ScanID: id.String()}); !errors.Is(err, tenablesc.ErrSensorUnavailable) {
			t.Fatalf("err = %v, want the sensor refusal", err)
		}
	})
}
