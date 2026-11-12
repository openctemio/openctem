package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func seedPracticeAsset(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, typ string, internetFacing bool) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type, is_internet_accessible) VALUES ($1, $2, $3, $4, $5)`,
		id.String(), tenant.String(), "practice-"+id.String()+".example.com", typ, internetFacing); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func newPracticeFinding(t *testing.T, tenant, asset shared.ID, src vulnerability.FindingSource, tool string, ft vulnerability.FindingType) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenant, asset, src, tool, vulnerability.SeverityHigh, "practice probe")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFingerprint("practice-" + shared.NewID().String())
	if ft != "" {
		f.SetFindingType(ft)
	}
	return f
}

func storedPractice(ctx context.Context, t *testing.T, db *sql.DB, tenant, id shared.ID) (string, sql.NullString) {
	t.Helper()
	var p string
	var reason sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT practice, practice_reason FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenant.String(), id.String()).Scan(&p, &reason); err != nil {
		t.Fatalf("read practice: %v", err)
	}
	return p, reason
}

// Every insert path derives the practice in Go from the finding and its
// asset's facts, and the finding reads it back.
func TestFindingPractice_DerivedOnInsert_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", false)
	repoAsset := seedPracticeAsset(ctx, t, db, tenant, "repository", false)
	app := seedPracticeAsset(ctx, t, db, tenant, "application", true)

	// Single-row create.
	cis := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceVA, "nessus", vulnerability.FindingTypeCompliance)
	if err := repo.Create(ctx, cis); err != nil {
		t.Fatalf("create: %v", err)
	}
	if p, r := storedPractice(ctx, t, db, tenant, cis.ID()); p != "compliance" || r.String != vulnerability.PracticeReasonBenchmarkCheck {
		t.Fatalf("compliance check stored as %s (%s)", p, r.String)
	}

	// Batch upsert, with asset facts from one query.
	batch := []*vulnerability.Finding{
		newPracticeFinding(t, tenant, host, vulnerability.FindingSourceVA, "nessus", ""),
		newPracticeFinding(t, tenant, repoAsset, vulnerability.FindingSourceSecret, "betterleaks", vulnerability.FindingTypeSecret),
		newPracticeFinding(t, tenant, app, vulnerability.FindingSourceDAST, "nuclei", ""),
		newPracticeFinding(t, tenant, host, vulnerability.FindingSourceDAST, "nuclei", ""),
	}
	want := []vulnerability.Practice{vulnerability.PracticeInfra, vulnerability.PracticeASPM, vulnerability.PracticeExternal, vulnerability.PracticeInfra}
	res, err := repo.CreateBatchWithResult(ctx, batch)
	if err != nil || len(res.Errors) > 0 {
		t.Fatalf("batch: %v %v", err, res)
	}
	for i, f := range batch {
		got, err := repo.GetByID(ctx, tenant, f.ID())
		if err != nil {
			t.Fatal(err)
		}
		if got.Practice() != want[i] || got.PracticeReason() == "" {
			t.Fatalf("finding %d: practice %s (%s), want %s", i, got.Practice(), got.PracticeReason(), want[i])
		}
	}

	// Update keeps the practice (no asset facts needed, nothing changes it).
	got, err := repo.GetByID(ctx, tenant, cis.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	if p, _ := storedPractice(ctx, t, db, tenant, cis.ID()); p != "compliance" {
		t.Fatalf("practice after update = %s", p)
	}
}

// A row written before the column (practice_reason NULL) takes the derived
// practice on its next sighting; a closed finding keeps its practice.
func TestFindingPractice_Resighting_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", false)

	legacyFP := "practice-legacy-" + shared.NewID().String()
	closedFP := "practice-closed-" + shared.NewID().String()
	for _, row := range []struct{ fp, status string }{{legacyFP, "new"}, {closedFP, "resolved"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, finding_type)
			VALUES ($1, $2, 'va', 'nessus', 'legacy', 'high', $3, $4, 'compliance')`, tenant.String(), host.String(), row.fp, row.status); err != nil {
			t.Fatal(err)
		}
	}
	again := []*vulnerability.Finding{
		newPracticeFinding(t, tenant, host, vulnerability.FindingSourceVA, "nessus", vulnerability.FindingTypeCompliance),
		newPracticeFinding(t, tenant, host, vulnerability.FindingSourceVA, "nessus", vulnerability.FindingTypeCompliance),
	}
	again[0].SetFingerprint(legacyFP)
	again[1].SetFingerprint(closedFP)
	if _, err := repo.CreateBatchWithResult(ctx, again); err != nil {
		t.Fatal(err)
	}
	var legacyP, closedP string
	var closedReason sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT practice FROM findings WHERE tenant_id = $1 AND fingerprint = $2`, tenant.String(), legacyFP).Scan(&legacyP); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT practice, practice_reason FROM findings WHERE tenant_id = $1 AND fingerprint = $2`, tenant.String(), closedFP).Scan(&closedP, &closedReason); err != nil {
		t.Fatal(err)
	}
	if legacyP != "compliance" {
		t.Fatalf("legacy open row after a sighting = %s, want compliance", legacyP)
	}
	if closedP != "other" || closedReason.Valid {
		t.Fatalf("closed row moved to %s (%v): closed findings are never re-derived", closedP, closedReason)
	}
}

// The asset facts are read only within the finding's tenant: another
// tenant's asset id reads as no asset.
func TestLoadPracticeAssetFacts_TenantPinned_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	a := seedTestTenant(ctx, t, db)
	b := seedTestTenant(ctx, t, db)
	bAsset := seedPracticeAsset(ctx, t, db, b, "repository", true)
	got, err := LoadPracticeAssetFacts(ctx, db, a, []string{bAsset.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("tenant A read tenant B's asset facts: %v", got)
	}
	got, err = LoadPracticeAssetFacts(ctx, db, b, []string{bAsset.String()})
	if err != nil || got[bAsset.String()].AssetType != "repository" || !got[bAsset.String()].AssetInternetFacing {
		t.Fatalf("own tenant facts = %v, %v", got, err)
	}
}

// A finding with its asset's facts attached (ingest) is derived from them;
// the others of the same batch still read their asset's facts, pinned to
// the tenant.
func TestFindingPractice_AttachedFacts_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", false)
	app := seedPracticeAsset(ctx, t, db, tenant, "application", false)

	// The stored row says not internet-facing; the attached facts (what the
	// ingest holds after its own upsert) say facing, and win.
	attached := newPracticeFinding(t, tenant, app, vulnerability.FindingSourceDAST, "nuclei", "")
	attached.AttachPracticeAssetFacts(vulnerability.PracticeAssetFacts{AssetType: "application", AssetInternetFacing: true})
	looked := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceDAST, "nuclei", "")
	if _, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{attached, looked}); err != nil {
		t.Fatal(err)
	}
	if p, r := storedPractice(ctx, t, db, tenant, attached.ID()); p != "external" || r.String != vulnerability.PracticeReasonOutsideInCheck {
		t.Fatalf("attached facts: practice %s (%s), want external", p, r.String)
	}
	if p, r := storedPractice(ctx, t, db, tenant, looked.ID()); p != "infra" || r.String != vulnerability.PracticeReasonInternalCheck {
		t.Fatalf("looked-up facts: practice %s (%s), want infra", p, r.String)
	}
}
