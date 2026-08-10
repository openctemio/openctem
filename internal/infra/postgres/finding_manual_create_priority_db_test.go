package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/app/finding"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// fakeEPSSRepo / fakeKEVRepo / fakeRuleRepo / fakeAuditRepo are minimal stand-ins
// for the enrichment side of the classifier so the test doesn't have to stand up
// the full EPSS/KEV/rule graph. The classification outcome under test is driven
// entirely by the seeded asset (public exposure) + critical severity, which the
// domain classifier maps to P1 ("Critical severity, reachable, no compensating
// controls").
type fakeEPSSRepo struct{}

func (fakeEPSSRepo) GetByCVEIDs(_ context.Context, _ []string) (map[string]finding.EPSSData, error) {
	return map[string]finding.EPSSData{}, nil
}

type fakeKEVRepo struct{}

func (fakeKEVRepo) GetByCVEIDs(_ context.Context, _ []string) (map[string]finding.KEVData, error) {
	return map[string]finding.KEVData{}, nil
}

type fakeRuleRepo struct{}

func (fakeRuleRepo) ListActiveByTenant(_ context.Context, _ shared.ID) ([]*vulnerability.PriorityOverrideRule, error) {
	return nil, nil
}

type fakeAuditRepo struct{}

func (fakeAuditRepo) LogChange(_ context.Context, _ finding.PriorityAuditEntry) error { return nil }

// seedPublicAsset creates a throwaway host asset with public exposure + high
// criticality so the priority classifier derives attacker-reachability from the
// asset's exposure level. Cleaned up via the tenant cascade.
func seedPublicAsset(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality)
		 VALUES ($1, $2, $3, 'host', 'public', 'high')`,
		id.String(), tenantID.String(), "probe-"+id.String())
	if err != nil {
		t.Fatalf("seed public asset: %v", err)
	}
	return id
}

// TestCreateFinding_ManualPersistsPriorityClass is the regression guard for the
// CTEM gap where manually-created findings (VulnerabilityService.CreateFinding,
// source='manual') bypassed the priority/SLA "brain" that only the ingest path
// ran. On live, all 61 source='manual' findings carried priority_class = NULL
// and were invisible to the P0-P3 dashboards, the priority queue, and SLA.
//
// This drives CreateFinding end to end against a real database and asserts the
// PERSISTED row (read back WITHOUT any intervening Update) has a non-NULL
// priority_class equal to the class the domain classifier derives for the
// inputs: critical severity on a public-exposure asset -> P1
// ("Critical severity, reachable, no compensating controls").
//
// EnrichAndClassifyBatch only mutates the finding in memory, so this passes only
// because the service classifies BEFORE the INSERT (priority_class has always
// been in the Create() column list). Skipped unless DATABASE_URL is set.
func TestCreateFinding_ManualPersistsPriorityClass(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	log := logger.NewNop()
	findingRepo := NewFindingRepository(&DB{DB: db})
	assetRepo := NewAssetRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedPublicAsset(ctx, t, db, tenantID)

	// Real classifier (same type wired in cmd/server), fed real finding+asset
	// repos and fake enrichment repos. vulnRepo is nil — CreateFinding never
	// touches it.
	classifier := finding.NewPriorityClassificationService(
		findingRepo, assetRepo,
		fakeEPSSRepo{}, fakeKEVRepo{},
		fakeRuleRepo{}, fakeAuditRepo{},
		log,
	)

	svc := finding.NewVulnerabilityService(nil, findingRepo, log)
	svc.SetAssetRepository(assetRepo)
	svc.SetPriorityClassifier(classifier)

	f, err := svc.CreateFinding(ctx, finding.CreateFindingInput{
		TenantID: tenantID.String(),
		AssetID:  assetID.String(),
		Source:   "manual",
		ToolName: "manual-entry",
		Message:  "manually-created critical finding on a public asset",
		Severity: "critical",
	})
	if err != nil {
		t.Fatalf("create finding: %v", err)
	}
	defer func() { _ = findingRepo.Delete(ctx, tenantID, f.ID()) }()

	// Read back WITHOUT any Update — proves the INSERT itself persisted the class.
	got, err := findingRepo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}

	pc := got.PriorityClass()
	if pc == nil {
		t.Fatalf("priority_class NULL on manually-created finding — the priority brain did not run (the exact live gap)")
	}
	if *pc != vulnerability.PriorityP1 {
		t.Errorf("priority_class = %q, want %q (critical severity on public-exposure asset)", *pc, vulnerability.PriorityP1)
	}
}
