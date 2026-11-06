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

// "Scan now" with a Tenable.sc connector on a migrated database: chosen
// assets of the caller's data scope are scanned through the connector with
// its coverage policy, repository and zone, as a manual run of one hidden
// on-demand scan per connector. Another tenant's integration or asset, and
// an asset outside the caller's scope, are not found.
func TestTenableSCScanNow(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenant, other := seedLifecycleTenant(ctx, t, db), seedLifecycleTenant(ctx, t, db)
	member, admin := seedActUser(t, db), seedActUser(t, db)
	mine := seedActAsset(t, db, tenant, "mine.example.com")
	theirs := seedActAsset(t, db, tenant, "theirs.example.com")
	foreignAsset := seedActAsset(t, db, other, "foreign.example.com")
	grantScope(t, db, tenant, member, mine)
	seedScopeTarget(t, db, tenant, "domain", "*.example.com")

	sensorID := seedReportingSensor(t, db, tenant, tenablesc.ToolName)
	otherSensor := seedReportingSensor(t, db, other, tenablesc.ToolName)

	intRepo := postgres.NewIntegrationRepository(pg)
	newConnector := func(tn, sn shared.ID, coverage bool) *integration.Integration {
		i := integration.NewIntegration(shared.NewID(), tn, "sc-"+shared.NewID().String()[28:], integration.CategorySecurity,
			integration.ProviderTenable, integration.AuthTypeAPIKey)
		cfg := map[string]any{"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": sn.String(), "instance": "sc-prod"}
		if coverage {
			cfg["coverage_policy_id"] = float64(1000003)
			cfg["coverage_repository_id"] = float64(5)
			cfg["coverage_max_scan_seconds"] = float64(3600)
		}
		i.SetConfig(cfg)
		i.SetMetadata(map[string]any{"tenable_sync": map[string]any{"catalog": map[string]any{
			"policies":          []any{map[string]any{"id": 1000003, "name": "Basic Network Scan"}},
			"scan_repositories": []any{map[string]any{"id": 5, "name": "Datacenter"}},
		}}})
		if err := intRepo.Create(ctx, i); err != nil {
			t.Fatalf("create integration: %v", err)
		}
		return i
	}
	conn := newConnector(tenant, sensorID, true)
	bare := newConnector(tenant, sensorID, false)
	foreignConn := newConnector(other, otherSensor, true)

	connector := tenablesc.NewService(intRepo, postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg),
		postgres.NewFindingRepository(pg), nil, logger.NewNop())
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithActScope(actScopeChecker(db, admin)), scansvc.WithConnectorScans(connector),
		scansvc.WithAttributionGate(ownershipGate(db)))
	asAdmin := asCaller(ctx, datascope.Caller{UserID: admin.String(), IsAdmin: true})
	asMember := asCaller(ctx, datascope.Caller{UserID: member.String()})

	start := func(c context.Context, user shared.ID, intg *integration.Integration, assets ...shared.ID) (*shared.ID, error) {
		run, err := svc.StartConnectorScan(c, scansvc.ConnectorScanNowInput{
			TenantID: tenant, UserID: user, IntegrationID: intg.ID(), AssetIDs: assets,
		})
		if err != nil {
			return nil, err
		}
		return &run.ID, nil
	}

	t.Run("another tenant's integration is not found", func(t *testing.T) {
		if _, err := start(asAdmin, admin, foreignConn, mine); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("err = %v, want not found", err)
		}
	})
	t.Run("another tenant's asset is not found", func(t *testing.T) {
		if _, err := start(asAdmin, admin, conn, foreignAsset); !errors.Is(err, scansvc.ErrConnectorAssetsNotFound) {
			t.Fatalf("err = %v, want not found", err)
		}
	})
	t.Run("an asset outside the member's data scope is not found", func(t *testing.T) {
		if _, err := start(asMember, member, conn, mine, theirs); !errors.Is(err, scansvc.ErrConnectorAssetsNotFound) {
			t.Fatalf("err = %v, want not found", err)
		}
	})
	t.Run("a connector without coverage policy and repository is refused", func(t *testing.T) {
		if _, err := start(asAdmin, admin, bare, mine); !errors.Is(err, tenablesc.ErrOnDemandNeedsCoverageConfig) {
			t.Fatalf("err = %v, want the coverage config refusal", err)
		}
	})
	t.Run("more than 50 assets are refused", func(t *testing.T) {
		ids := make([]shared.ID, 51)
		for i := range ids {
			ids[i] = shared.NewID()
		}
		if _, err := start(asAdmin, admin, conn, ids...); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("err = %v, want validation", err)
		}
	})

	var firstScan string
	readRun := func(t *testing.T, runID shared.ID) (scanID string, p tenablesc.ScanPayload) {
		t.Helper()
		var payload []byte
		var typ, pinned string
		if err := db.QueryRowContext(ctx, `SELECT type, sensor_id::text, payload FROM commands
			WHERE tenant_id = $1 AND payload->>'run_id' = $2`, tenant.String(), runID.String()).Scan(&typ, &pinned, &payload); err != nil {
			t.Fatalf("read command: %v", err)
		}
		if typ != "connector_scan" || pinned != sensorID.String() {
			t.Fatalf("type %q sensor %q", typ, pinned)
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM commands WHERE tenant_id = $1 AND payload->>'run_id' = $2`,
			tenant.String(), runID.String()).Scan(&n); err != nil || n != 1 {
			t.Fatalf("commands of the run = %d (%v), want 1", n, err)
		}
		var trigger, by string
		if err := db.QueryRowContext(ctx, `SELECT scan_id::text, trigger_type, COALESCE(triggered_by, '') FROM scan_runs WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), runID.String()).Scan(&scanID, &trigger, &by); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if trigger != "manual" {
			t.Fatalf("trigger %q, want manual", trigger)
		}
		return scanID, p
	}

	t.Run("a member scans an asset of their scope", func(t *testing.T) {
		runID, err := start(asMember, member, conn, mine)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		scanID, p := readRun(t, *runID)
		firstScan = scanID
		if !slices.Equal(p.Targets, []string{"mine.example.com"}) {
			t.Fatalf("targets %v", p.Targets)
		}
		if p.IntegrationID != conn.ID().String() || p.PolicyID != 1000003 || p.RepositoryID != 5 || p.MaxScanSeconds != 3600 {
			t.Fatalf("payload %+v", p)
		}
		var adHoc bool
		var tags []byte
		var targets []byte
		if err := db.QueryRowContext(ctx, `SELECT ad_hoc, to_json(tags), to_json(targets) FROM scans WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), scanID).Scan(&adHoc, &tags, &targets); err != nil {
			t.Fatal(err)
		}
		if !adHoc || string(tags) != `["`+scansvc.ConnectorOnDemandTag+`"]` {
			t.Fatalf("scan ad_hoc=%v tags=%s", adHoc, tags)
		}
		if string(targets) != "[]" && string(targets) != "null" {
			t.Fatalf("the hidden scan stores targets %s, want none", targets)
		}
	})

	t.Run("a second call reuses the on-demand scan", func(t *testing.T) {
		runID, err := start(asAdmin, admin, conn, theirs, mine)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		scanID, p := readRun(t, *runID)
		if scanID != firstScan {
			t.Fatalf("scan %s, want the same on-demand scan %s", scanID, firstScan)
		}
		if !slices.Equal(p.Targets, []string{"theirs.example.com", "mine.example.com"}) {
			t.Fatalf("targets %v", p.Targets)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE tenant_id = $1 AND $2 = ANY(tags)`,
			tenant.String(), scansvc.ConnectorOnDemandTag).Scan(&n); err != nil || n != 1 {
			t.Fatalf("on-demand scans = %d (%v), want 1", n, err)
		}
	})
}
