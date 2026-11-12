package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Neither finding INSERT wrote rule_name, so the scanner's rule name (a
// nuclei template's, a semgrep rule's, the betterleaks rule description) was
// stored only when the same finding was reported again (RFC-044 P0; the tags
// half of the same gap was #893). A re-sighting keeps the first non-empty
// name and fills a missing one.
func TestFindingRuleName_CreateAndUpsert_DB(t *testing.T) {
	ctx := context.Background()
	db := openOccDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	newFinding := func(t *testing.T, fp, ruleName string) *vulnerability.Finding {
		t.Helper()
		f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceDAST,
			"nuclei", vulnerability.SeverityMedium, "rule name probe")
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint(fp)
		f.SetRuleID("exposed-git-config")
		f.SetRuleName(ruleName)
		return f
	}
	nameOf := func(t *testing.T, id shared.ID) string {
		t.Helper()
		got, err := repo.GetByID(ctx, tenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		return got.RuleName()
	}

	// Manual/pentest create.
	manual := newFinding(t, "rn-create-"+shared.NewID().String(), "Git config exposure")
	if err := repo.Create(ctx, manual); err != nil {
		t.Fatal(err)
	}
	if got := nameOf(t, manual.ID()); got != "Git config exposure" {
		t.Fatalf("Create: rule_name %q, want %q", got, "Git config exposure")
	}

	// Ingest insert.
	fp := "rn-upsert-" + shared.NewID().String()
	first := newFinding(t, fp, "Git config exposure")
	if res, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{first}); err != nil || res.Created != 1 {
		t.Fatalf("batch insert: %v %+v", err, res)
	}
	if got := nameOf(t, first.ID()); got != "Git config exposure" {
		t.Fatalf("batch insert: rule_name %q, want %q", got, "Git config exposure")
	}

	// A re-sighting through ON CONFLICT with another name keeps the first.
	again := newFinding(t, fp, "Renamed template")
	if _, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{again}); err != nil {
		t.Fatal(err)
	}
	if got := nameOf(t, first.ID()); got != "Git config exposure" {
		t.Errorf("re-sighting: rule_name %q, want the first one kept", got)
	}

	// A first sighting with no name gets one from a later report.
	fp2 := "rn-fill-" + shared.NewID().String()
	unnamed := newFinding(t, fp2, "")
	if _, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{unnamed}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{newFinding(t, fp2, "Late name")}); err != nil {
		t.Fatal(err)
	}
	if got := nameOf(t, unnamed.ID()); got != "Late name" {
		t.Errorf("fill: rule_name %q, want %q", got, "Late name")
	}
}
