package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Content packs against a real schema (migration 001384): tenant isolation
// of packs and blobs, the composite blob key, uniqueness and revocation.
// Requires DATABASE_URL (CI applies every migration first).

func testPack(tenantID shared.ID, name, version, digest string) *contentpack.Pack {
	return &contentpack.Pack{
		ID: shared.NewID(), TenantID: tenantID, Name: name, Version: version,
		Kind: contentpack.KindWordlist, Digest: digest, Tier: contentpack.TierT0,
		Status: contentpack.StatusActive, Source: contentpack.SourceUpload,
		Lint:      contentpack.LintReport{Tier: contentpack.TierT0, Files: 1, Items: 2},
		Signature: []byte(`{"payloadType":"x","payload":"e30=","signatures":[]}`),
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

func TestContentPackRepository_TenantIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewContentPackRepository(&DB{DB: sqlDB})
	tenantA := seedTestTenant(ctx, t, sqlDB)
	tenantB := seedTestTenant(ctx, t, sqlDB)
	digest := "sha256:" + strings.Repeat("ab", 32)

	blob := &contentpack.Blob{TenantID: tenantA, Digest: digest, SizeBytes: 2048, FileCount: 1, StorageKey: "k1", CreatedAt: time.Now()}
	if created, err := repo.CreateBlob(ctx, blob); err != nil || !created {
		t.Fatalf("create blob: %v %v", created, err)
	}
	if created, err := repo.CreateBlob(ctx, &contentpack.Blob{TenantID: tenantA, Digest: digest, SizeBytes: 2048, FileCount: 1, StorageKey: "k2", CreatedAt: time.Now()}); err != nil || created {
		t.Fatalf("second blob of a digest: %v %v", created, err)
	}
	if b, err := repo.GetBlob(ctx, tenantA, digest); err != nil || b.StorageKey != "k1" {
		t.Fatalf("get blob: %+v %v", b, err)
	}
	// SECURITY: a digest of another tenant is not found, and a pack cannot
	// point at another tenant's blob (composite foreign key).
	if _, err := repo.GetBlob(ctx, tenantB, digest); !errors.Is(err, contentpack.ErrNotFound) {
		t.Fatalf("cross-tenant blob: %v", err)
	}
	if err := repo.Create(ctx, testPack(tenantB, "w", "1", digest)); err == nil {
		t.Fatal("tenant B created a pack over tenant A's blob")
	}

	p := testPack(tenantA, "w", "1", digest)
	if err := repo.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, testPack(tenantA, "w", "1", digest)); !errors.Is(err, contentpack.ErrExists) {
		t.Fatalf("duplicate name and version: %v", err)
	}
	got, err := repo.GetByID(ctx, tenantA, p.ID)
	if err != nil || got.SizeBytes != 2048 || got.Lint.Items != 2 || got.Status != contentpack.StatusActive {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := repo.GetByID(ctx, tenantB, p.ID); !errors.Is(err, contentpack.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if list, total, err := repo.List(ctx, tenantB, contentpack.Filter{}, 10, 0); err != nil || total != 0 || len(list) != 0 {
		t.Fatalf("cross-tenant list: %d %v", total, err)
	}
	if list, total, err := repo.List(ctx, tenantA, contentpack.Filter{Kind: contentpack.KindWordlist, Status: contentpack.StatusActive}, 10, 0); err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("list: %d %v", total, err)
	}
	if err := repo.Revoke(ctx, tenantB, p.ID, nil, "x", time.Now()); !errors.Is(err, contentpack.ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if err := repo.Revoke(ctx, tenantA, p.ID, nil, "bad", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, tenantA, p.ID, nil, "again", time.Now()); !errors.Is(err, contentpack.ErrNotActive) {
		t.Fatalf("revoke twice: %v", err)
	}
	if got, _ := repo.GetByID(ctx, tenantA, p.ID); got.Status != contentpack.StatusRevoked || got.RevokedAt == nil || got.RevokeReason != "bad" {
		t.Fatalf("revoked: %+v", got)
	}
	if n, b, err := repo.Usage(ctx, tenantA); err != nil || n != 1 || b != 2048 {
		t.Fatalf("usage: %d %d %v", n, b, err)
	}
	// A blob a pack uses cannot be deleted from under it.
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM content_pack_blobs WHERE tenant_id = $1`, tenantA.String()); err == nil {
		t.Fatal("deleted a blob a pack uses")
	}
}
