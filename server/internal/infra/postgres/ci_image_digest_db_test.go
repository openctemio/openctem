package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Assets carrying an image digest are found within the tenant only, the
// repository itself excluded. Requires DATABASE_URL.
func TestCIAssetsWithImageDigest(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	digest := "sha256:" + strings.Repeat("d", 64)
	mk := func(tid shared.ID, typ, sub, props string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, properties)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6::jsonb)`, id.String(), tid.String(), "a-"+id.String(), typ, sub, props); err != nil {
			t.Fatalf("seed %s: %v", typ, err)
		}
		return id
	}
	repoID := mk(tenant, "repository", "", `{"note":"`+digest+`"}`)
	workload := mk(tenant, "kubernetes", "workload", `{"containers":[{"image":"ghcr.io/acme/api@`+digest+`"}]}`)
	mk(tenant, "host", "", `{"images":["ghcr.io/acme/other@sha256:`+strings.Repeat("e", 64)+`"]}`)
	mk(other, "kubernetes", "workload", `{"image":"x@`+digest+`"}`)

	got, err := repo.AssetsWithImageDigest(ctx, tenant, digest, repoID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != workload || got[0].Type != "kubernetes" || got[0].SubType != "workload" {
		t.Fatalf("assets = %+v", got)
	}
}
