package postgres

import (
	"context"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Neither finding INSERT (Create for manual and pentest findings, the batch
// upsert for ingest) wrote the tags column, so a new finding's tags were
// lost until an edit. Semantics checked here: create stores the tags, a
// re-sighting through the upsert merges (stored first, new appended, at most
// MaxFindingTags), and Update replaces (the PUT /findings/{id}/tags edit).
func TestFindingTags_CreateUpsertUpdate_DB(t *testing.T) {
	ctx := context.Background()
	db := openOccDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	newFinding := func(t *testing.T, fp string, tags []string) *vulnerability.Finding {
		t.Helper()
		f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST,
			"semgrep", vulnerability.SeverityHigh, "tag probe")
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint(fp)
		f.SetTags(tags)
		return f
	}
	tagsOf := func(t *testing.T, id shared.ID) []string {
		t.Helper()
		got, err := repo.GetByID(ctx, tenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		return got.Tags()
	}

	// Manual/pentest create.
	manual := newFinding(t, "tags-create-"+shared.NewID().String(), []string{"manual", "pci"})
	if err := repo.Create(ctx, manual); err != nil {
		t.Fatal(err)
	}
	if got := tagsOf(t, manual.ID()); !reflect.DeepEqual(got, []string{"manual", "pci"}) {
		t.Fatalf("Create: tags %v, want [manual pci]", got)
	}

	// Ingest insert, then a re-sighting of the same fingerprint (ON CONFLICT).
	fp := "tags-upsert-" + shared.NewID().String()
	first := newFinding(t, fp, []string{"a", "b"})
	if res, err := repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{first}); err != nil || res.Created != 1 {
		t.Fatalf("batch insert: %v %+v", err, res)
	}
	if got := tagsOf(t, first.ID()); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("batch insert: tags %v, want [a b]", got)
	}
	more := []string{"b", "c"}
	for i := 0; i < 60; i++ {
		more = append(more, "x"+string(rune('A'+i%26))+string(rune('a'+i/26)))
	}
	if err := repo.CreateBatch(ctx, []*vulnerability.Finding{newFinding(t, fp, more)}); err != nil {
		t.Fatal(err)
	}
	got := tagsOf(t, first.ID())
	if len(got) != vulnerability.MaxFindingTags || !reflect.DeepEqual(got[:3], []string{"a", "b", "c"}) {
		t.Fatalf("upsert merge: %d tags %v, want %d starting [a b c]", len(got), got, vulnerability.MaxFindingTags)
	}

	// Update replaces.
	f, err := repo.GetByID(ctx, tenantID, first.ID())
	if err != nil {
		t.Fatal(err)
	}
	f.SetTags([]string{"only"})
	if err := repo.Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	if got := tagsOf(t, first.ID()); !reflect.DeepEqual(got, []string{"only"}) {
		t.Fatalf("Update: tags %v, want [only]", got)
	}
}
