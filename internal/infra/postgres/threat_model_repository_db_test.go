package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatmodel"
	"github.com/openctemio/api/pkg/pagination"
)

// TestThreatModelRepository_SaveReplaceAndScope exercises the tx create/replace
// (delete-and-insert) path, tenant-scoping, threat filtering, and catalog reads
// against the real schema. Skipped unless DATABASE_URL is set.
func TestThreatModelRepository_SaveReplaceAndScope(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed threat model test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := shared.NewID()
	otherTenant := shared.NewID()
	for _, tid := range []shared.ID{tenantID, otherTenant} {
		slug := "tm-" + tid.String()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			tid.String(), "threatmodel-test", slug); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		defer func(id string) { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id) }(tid.String())
	}

	crownJewel := seedAsset(ctx, t, db, tenantID)
	repo := NewThreatModelRepository(&DB{DB: db})

	// --- First generation: model with 2 threats (1 open, 1 theoretical). ---
	scopeRef := crownJewel
	model, err := threatmodel.NewThreatModel(tenantID, threatmodel.ScopeCrownJewel, &scopeRef, "payments-db threat model")
	if err != nil {
		t.Fatalf("new model: %v", err)
	}
	model.TechniqueDatasetVersion = threatmodel.DefaultDatasetVersion
	model.InputHash = "hash-v1"

	openThreat := newTestThreat(t, tenantID, model.ID, threatmodel.StatusOpen, "T1190", "Initial Access", 0)
	theoThreat := newTestThreat(t, tenantID, model.ID, threatmodel.StatusTheoretical, "T1005", "Collection", 2)
	model.RecomputeRollups([]*threatmodel.ThreatModelThreat{openThreat, theoThreat})

	if err := repo.Save(ctx, model, []*threatmodel.ThreatModelThreat{openThreat, theoThreat}); err != nil {
		t.Fatalf("save v1: %v", err)
	}

	// Rollups: 2 total, 1 open, 0 addressed → coverage 0.
	got, err := repo.GetByID(ctx, tenantID, model.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.ThreatsTotal != 2 || got.ThreatsOpen != 1 || got.CoveragePct != 0 {
		t.Errorf("v1 rollups wrong: total=%d open=%d cov=%.1f", got.ThreatsTotal, got.ThreatsOpen, got.CoveragePct)
	}

	firstID := model.ID

	// --- Regenerate the SAME scope: id must be reused, threats replaced. ---
	model2, err := threatmodel.NewThreatModel(tenantID, threatmodel.ScopeCrownJewel, &scopeRef, "payments-db threat model")
	if err != nil {
		t.Fatalf("new model2: %v", err)
	}
	model2.InputHash = "hash-v2"
	// Different id assigned by constructor — Save must reconcile to the existing row.
	mitThreat := newTestThreat(t, tenantID, model2.ID, threatmodel.StatusMitigated, "T1190", "Initial Access", 0)
	model2.RecomputeRollups([]*threatmodel.ThreatModelThreat{mitThreat})
	if err := repo.Save(ctx, model2, []*threatmodel.ThreatModelThreat{mitThreat}); err != nil {
		t.Fatalf("save v2: %v", err)
	}
	if !model2.ID.Equals(firstID) {
		t.Errorf("expected reused model id %s, got %s", firstID, model2.ID)
	}

	// Exactly one model exists for the scope, with the replaced threat set.
	byScope, err := repo.GetByScope(ctx, tenantID, threatmodel.ScopeCrownJewel, &scopeRef)
	if err != nil {
		t.Fatalf("get by scope: %v", err)
	}
	if byScope.InputHash != "hash-v2" || byScope.ThreatsTotal != 1 || byScope.ThreatsMitigated != 1 {
		t.Errorf("v2 model not replaced correctly: %+v", byScope)
	}
	if byScope.CoveragePct != 100 {
		t.Errorf("expected coverage 100 (1 mitigated / 1), got %.1f", byScope.CoveragePct)
	}

	threats, err := repo.ListThreats(ctx, tenantID, firstID, threatmodel.ThreatFilter{})
	if err != nil {
		t.Fatalf("list threats: %v", err)
	}
	if len(threats) != 1 || threats[0].Status != threatmodel.StatusMitigated {
		t.Fatalf("expected 1 mitigated threat after replace, got %d: %+v", len(threats), threats)
	}

	// Filter by status returns nothing for 'open' now.
	openList, err := repo.ListThreats(ctx, tenantID, firstID, threatmodel.ThreatFilter{Status: threatmodel.StatusOpen})
	if err != nil {
		t.Fatalf("list open threats: %v", err)
	}
	if len(openList) != 0 {
		t.Errorf("expected 0 open threats after replace, got %d", len(openList))
	}

	// --- Tenant isolation: otherTenant cannot see the model. ---
	if _, err := repo.GetByID(ctx, otherTenant, firstID); !isNotFound(err) {
		t.Errorf("expected ErrNotFound for cross-tenant GetByID, got %v", err)
	}
	models, total, err := repo.ListModels(ctx, otherTenant, threatmodel.ModelFilter{}, pagination.Pagination{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("list models other tenant: %v", err)
	}
	if total != 0 || len(models) != 0 {
		t.Errorf("expected 0 models for other tenant, got total=%d len=%d", total, len(models))
	}

	// Owning tenant lists exactly one.
	models, total, err = repo.ListModels(ctx, tenantID, threatmodel.ModelFilter{ScopeType: threatmodel.ScopeCrownJewel}, pagination.Pagination{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("list models: %v", err)
	}
	if total != 1 || len(models) != 1 {
		t.Errorf("expected 1 model for owning tenant, got total=%d len=%d", total, len(models))
	}

	// --- Delete cascades to threats. ---
	if err := repo.Delete(ctx, tenantID, firstID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, tenantID, firstID); !isNotFound(err) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestThreatModelRepository_CatalogReads validates the global (tenant-agnostic)
// catalog reads against the seeded attack-16.1 dataset.
func TestThreatModelRepository_CatalogReads(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping catalog read test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewThreatModelRepository(&DB{DB: db})

	mitigations, err := repo.ListTechniqueMitigations(ctx, threatmodel.DefaultDatasetVersion)
	if err != nil {
		t.Fatalf("list mitigations: %v", err)
	}
	if len(mitigations) == 0 {
		t.Fatal("expected seeded mitigations, got 0 (is migration 000190 applied?)")
	}
	// T1190 must map to at least one mitigation.
	var t1190 int
	for _, m := range mitigations {
		if m.TechniqueID == "T1190" {
			t1190++
			if m.MitigationID == "" || m.MitigationName == "" {
				t.Errorf("T1190 mitigation missing id/name: %+v", m)
			}
		}
	}
	if t1190 == 0 {
		t.Error("expected T1190 mitigations in catalog")
	}

	applic, err := repo.ListApplicability(ctx, threatmodel.DefaultDatasetVersion)
	if err != nil {
		t.Fatalf("list applicability: %v", err)
	}
	if len(applic) == 0 {
		t.Fatal("expected seeded applicability rows, got 0")
	}
}

func newTestThreat(t *testing.T, tenantID, modelID shared.ID, status threatmodel.ThreatStatus, technique, tactic string, hop int) *threatmodel.ThreatModelThreat {
	t.Helper()
	th, err := threatmodel.NewThreatModelThreat(tenantID, modelID, status)
	if err != nil {
		t.Fatalf("new threat: %v", err)
	}
	th.TechniqueID = technique
	th.Tactic = tactic
	th.HopIndex = hop
	th.Score = float64(10 - hop)
	return th
}

func isNotFound(err error) bool {
	return err != nil && shared.IsNotFound(err)
}
