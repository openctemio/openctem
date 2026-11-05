package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func storedTags(t *testing.T, f *renameFixture, tenant shared.ID, name string) []string {
	t.Helper()
	var tags pq.StringArray
	if err := f.db.QueryRowContext(context.Background(), `SELECT tags FROM assets WHERE tenant_id=$1 AND name=$2`, tenant.String(), name).Scan(&tags); err != nil {
		t.Fatalf("read tags: %v", err)
	}
	return tags
}

// Every write path applies the shared tag validator: the create and update
// API refuse a bad tag with a validation error, an import drops it, and a tag
// that is already on an asset never blocks a save. Tags of another tenant's
// asset are untouched.
func TestAssetTags_SharedValidatorOnEveryWritePath(t *testing.T) {
	f := newRenameFixture(t, "tag-validator")
	ctx := context.Background()
	svc := asset.NewAssetService(postgres.NewAssetRepository(&postgres.DB{DB: f.db}), logger.NewNop())
	tid := f.tenant.String()

	// create: refused
	for _, bad := range []string{strings.Repeat("a", 51), "bug-bounty", "sys:x", "a\u202eb", "<b>"} {
		_, err := svc.CreateAsset(ctx, asset.CreateAssetInput{TenantID: tid, Name: "bad-" + "x.example.internal", Type: "host", Criticality: "low", Tags: []string{bad}})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("create with tag %q: want validation error, got %v", bad, err)
		}
	}
	a, err := svc.CreateAsset(ctx, asset.CreateAssetInput{TenantID: tid, Name: "ok.example.internal", Type: "host", Criticality: "low", Tags: []string{"team:payments"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// update: a new bad tag is refused, a good one is added, the old stays
	if _, err := svc.UpdateAsset(ctx, a.ID().String(), tid, asset.UpdateAssetInput{Tags: []string{"team:payments", "sys:owner"}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("update with reserved tag: want validation error, got %v", err)
	}
	if _, err := svc.UpdateAsset(ctx, a.ID().String(), tid, asset.UpdateAssetInput{Tags: []string{"team:payments", "env:prod"}}); err != nil {
		t.Fatalf("update: %v", err)
	}

	// legacy tag (over the limit) written directly stays savable
	long := strings.Repeat("L", 80)
	if _, err := f.db.ExecContext(context.Background(), `UPDATE assets SET tags = tags || $3::text WHERE tenant_id=$1 AND name=$2`, tid, "ok.example.internal", long); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateAsset(ctx, a.ID().String(), tid, asset.UpdateAssetInput{Tags: []string{"team:payments", "env:prod", long, "extra"}}); err != nil {
		t.Fatalf("a legacy tag must not make the asset unsavable: %v", err)
	}

	// ingest: hostile tags dropped, good kept
	f.ingest(t, ctis.Asset{ID: "h1", Type: ctis.AssetTypeHost, Value: "ing.example.internal", Name: "ing.example.internal",
		Tags: []string{strings.Repeat("z", 200), "bug-bounty", "a\u200bb", "fine"}})
	got := storedTags(t, f, f.tenant, "ing.example.internal")
	if len(got) != 1 || got[0] != "fine" {
		t.Fatalf("ingest stored %v, want [fine]", got)
	}

	// another tenant's asset of the same name is untouched
	other := createTestTenant(t, f.db, "tag-validator-other")
	t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM assets WHERE tenant_id=$1`, other.String())
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id=$1`, other.String())
	})
	if _, err := f.db.ExecContext(context.Background(), `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, tags) VALUES ($1,$2,'ing.example.internal','host','low','active',ARRAY['theirs'])`, shared.NewID().String(), other.String()); err != nil {
		t.Fatal(err)
	}
	f.ingest(t, ctis.Asset{ID: "h1", Type: ctis.AssetTypeHost, Value: "ing.example.internal", Name: "ing.example.internal", Tags: []string{"more"}})
	if got := storedTags(t, f, other, "ing.example.internal"); len(got) != 1 || got[0] != "theirs" {
		t.Fatalf("another tenant's tags changed: %v", got)
	}
}
