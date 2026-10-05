package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The human/API create refuses a duplicate (409) while sensor ingest keeps
// its own merge path: a report naming an existing asset updates that asset,
// whether a person or an earlier report created it.
func TestAssetCreateConflict_IngestStillMerges(t *testing.T) {
	f := newRenameFixture(t, "create-vs-ingest")
	ctx := context.Background()
	svc := app.NewAssetService(postgres.NewAssetRepository(&postgres.DB{DB: f.db}), logger.NewNop())

	const name = "dup-ingest.example.internal"
	created, err := svc.CreateAsset(ctx, app.CreateAssetInput{
		TenantID: f.tenant.String(), Name: name, Type: "host", Criticality: "high",
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// A second create is a conflict naming the asset (no data scope wired).
	_, err = svc.CreateAsset(ctx, app.CreateAssetInput{
		TenantID: f.tenant.String(), Name: name, Type: "host", Criticality: "low",
	})
	var dup *app.DuplicateAssetError
	if !errors.As(err, &dup) || dup.ExistingID != created.ID() {
		t.Fatalf("second create error = %v, want a conflict naming %s", err, created.ID())
	}

	// Ingest of the same host merges into it: still one asset, same id.
	ids, _ := f.ingest(t, ctis.Asset{ID: "h1", Type: ctis.AssetTypeHost, Value: name, Name: name})
	if got := ids["h1"]; got != created.ID() {
		t.Errorf("ingest mapped the host to %s, want the existing asset %s", got, created.ID())
	}
	all := f.assets(t)
	if len(all) != 1 {
		t.Fatalf("assets after create + ingest = %d, want 1: %v", len(all), all)
	}
	if a := all[created.ID().String()]; a.criticality != "high" {
		t.Errorf("ingest changed the criticality to %s", a.criticality)
	}
}
