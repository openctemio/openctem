package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// findingMutator adapts the postgres FindingRepository (GetByID) to the
// validation.FindingMutator + VerdictRecorder interfaces, mirroring cmd/server's
// adapter.
type findingMutator struct{ repo *postgres.FindingRepository }

func (a findingMutator) Get(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error) {
	return a.repo.GetByID(ctx, tenantID, findingID)
}
func (a findingMutator) Update(ctx context.Context, f *vulnerability.Finding) error {
	return a.repo.Update(ctx, f)
}
func (a findingMutator) RecordVerdict(ctx context.Context, tenantID, findingID shared.ID, verdict validation.Verdict, downgradedAt *time.Time) error {
	return a.repo.StampValidationVerdict(ctx, tenantID, findingID, string(verdict), downgradedAt)
}

// TestValidationEvidence_Repository_RoundTrip exercises the postgres
// ValidationEvidenceRepository against real SQL: the JSONB Evidence envelope
// (including a shared.ID Target.AssetID) must survive a Create→ListByFinding
// round trip, NULL vs set simulation_run_id must scan correctly, and rows must
// come back newest-first.
func TestValidationEvidence_Repository_RoundTrip(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}

	tenantID := createTestTenant(t, sqlDB, "valev")
	assetID := createTestAsset(t, sqlDB, tenantID, "valev-asset")
	findingID := createTestFinding(t, sqlDB, tenantID, assetID, "validation evidence")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	repo := postgres.NewValidationEvidenceRepository(db)
	store := validation.NewEvidenceStore(repo)
	ctx := context.Background()

	simRunID := shared.NewID()
	// First (older) record — with a simulation run id + asset target + raw meta.
	if _, err := store.Record(ctx, tenantID, findingID, &simRunID, validation.Evidence{
		ExecutorKind: "nuclei",
		Technique:    "T1190",
		Target:       validation.Target{AssetID: assetID, Type: "web_url", Address: "https://app.example"},
		Outcome:      validation.OutcomeDetected,
		Summary:      "still exploitable",
		Artifacts:    []string{"art-1"},
		RawMeta:      map[string]any{"status_code": "200"},
	}); err != nil {
		t.Fatalf("record #1: %v", err)
	}
	// Second (newer) record — no simulation run id.
	if _, err := store.Record(ctx, tenantID, findingID, nil, validation.Evidence{
		ExecutorKind: "safe-check",
		Technique:    "T1046",
		Outcome:      validation.OutcomeNotDetected,
		Summary:      "exposure gone",
	}); err != nil {
		t.Fatalf("record #2: %v", err)
	}

	list, err := store.ListForFinding(ctx, tenantID, findingID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 evidence rows, got %d", len(list))
	}

	// Newest first.
	if list[0].Evidence.Outcome != validation.OutcomeNotDetected {
		t.Errorf("rows not newest-first: [0] outcome = %q", list[0].Evidence.Outcome)
	}
	if list[0].SimulationRunID != nil {
		t.Errorf("newest row should have NULL simulation_run_id, got %v", list[0].SimulationRunID)
	}

	// Older row — JSONB round-trip of the full Evidence incl shared.ID target.
	older := list[1]
	if older.SimulationRunID == nil || *older.SimulationRunID != simRunID {
		t.Errorf("simulation_run_id round-trip failed: %v", older.SimulationRunID)
	}
	if older.Evidence.Target.AssetID != assetID {
		t.Errorf("target asset id round-trip failed: got %v want %v", older.Evidence.Target.AssetID, assetID)
	}
	if older.Evidence.Technique != "T1190" || older.Evidence.ExecutorKind != "nuclei" {
		t.Errorf("evidence fields round-trip failed: %+v", older.Evidence)
	}
	if older.Evidence.RawMeta["status_code"] != "200" {
		t.Errorf("raw_meta round-trip failed: %v", older.Evidence.RawMeta)
	}
	if len(older.Evidence.Artifacts) != 1 || older.Evidence.Artifacts[0] != "art-1" {
		t.Errorf("artifacts round-trip failed: %v", older.Evidence.Artifacts)
	}
}

// TestValidationEvidence_Ingest_TenantGuard verifies the security guard against
// real SQL: an agent in tenant B cannot record evidence against tenant A's
// finding (the cross-tenant id the FK alone would not catch), and no row is
// written.
func TestValidationEvidence_Ingest_TenantGuard(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	ctx := context.Background()

	tenantA := createTestTenant(t, sqlDB, "valev-a")
	tenantB := createTestTenant(t, sqlDB, "valev-b")
	assetA := createTestAsset(t, sqlDB, tenantA, "valev-a-asset")
	findingA := createTestFinding(t, sqlDB, tenantA, assetA, "tenant A finding")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantA, tenantB) })

	repo := postgres.NewValidationEvidenceRepository(db)
	findingRepo := postgres.NewFindingRepository(db)
	ingest := validation.NewEvidenceIngestService(
		validation.NewEvidenceStore(repo), findingMutator{repo: findingRepo}, nil, findingMutator{repo: findingRepo}, log,
	)

	// Tenant B tries to record evidence against tenant A's finding.
	_, err := ingest.Ingest(ctx, tenantB, findingA, nil, validation.Evidence{
		ExecutorKind: "safe-check", Outcome: validation.OutcomeNotDetected,
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant ingest should fail with ErrNotFound, got %v", err)
	}

	// No evidence may have been written for that finding under tenant B.
	rows, err := repo.ListByFinding(ctx, tenantB, findingA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("cross-tenant evidence must not be recorded, found %d rows", len(rows))
	}
}

// TestValidationEvidence_Ingest_TransitionsFinding verifies the full ingest path
// against real SQL: a not_detected outcome on a fix_applied finding records
// evidence and transitions the finding to resolved.
func TestValidationEvidence_Ingest_TransitionsFinding(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "valev-tx")
	assetID := createTestAsset(t, sqlDB, tenantID, "valev-tx-asset")
	findingID := createTestFinding(t, sqlDB, tenantID, assetID, "to resolve")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	findingRepo := postgres.NewFindingRepository(db)

	// Promote the finding new → confirmed → in_progress → fix_applied.
	f, err := findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
		vulnerability.FindingStatusFixApplied,
	} {
		if terr := f.TransitionStatus(st, "", nil); terr != nil {
			t.Fatalf("transition to %s: %v", st, terr)
		}
	}
	if uerr := findingRepo.Update(ctx, f); uerr != nil {
		t.Fatalf("persist fix_applied: %v", uerr)
	}

	ingest := validation.NewEvidenceIngestService(
		validation.NewEvidenceStore(postgres.NewValidationEvidenceRepository(db)),
		findingMutator{repo: findingRepo}, nil, findingMutator{repo: findingRepo}, log,
	)

	res, err := ingest.Ingest(ctx, tenantID, findingID, nil, validation.Evidence{
		ExecutorKind: "safe-check", Technique: "T1046", Outcome: validation.OutcomeNotDetected,
		Summary: "exposure no longer reproduces",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.StatusChanged {
		t.Error("expected the finding status to change")
	}

	reloaded, err := findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Status() != vulnerability.FindingStatusResolved {
		t.Errorf("finding status = %s, want resolved", reloaded.Status())
	}
}
