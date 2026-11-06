package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func capTestDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	old := maxSubResourceRows
	maxSubResourceRows = 3
	t.Cleanup(func() { maxSubResourceRows = old })
	return db, ctx
}

// A parent with more attachments than the cap lists at most the cap, oldest
// first, and never another tenant's rows.
func TestAttachmentListByContext_Capped_DB(t *testing.T) {
	db, ctx := capTestDB(t)
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	for _, tn := range []shared.ID{tenant, tenant, tenant, tenant, tenant, other} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO attachments (tenant_id, filename, content_type, size, storage_key, context_type, context_id)
			 VALUES ($1, 'f', 'text/plain', 1, $2, 'finding', 'ctx-1')`, tn.String(), "k-"+shared.NewID().String()); err != nil {
			t.Fatalf("seed attachment: %v", err)
		}
	}
	got, err := NewAttachmentRepository(&DB{DB: db}).ListByContext(ctx, tenant, "finding", "ctx-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("listed %d attachments, want the cap of 3", len(got))
	}
}

// Owners of one asset are capped; the primary owner sorts first so the cap
// never drops it.
func TestListAssetOwnersWithNames_Capped_DB(t *testing.T) {
	db, ctx := capTestDB(t)
	tenant := seedTestTenant(ctx, t, db)
	assetID := seedOwnedAsset(ctx, t, db, tenant, nil)
	for i := 0; i < 5; i++ {
		u := seedGroupsUser(ctx, t, db, "cap.example.com")
		if _, err := db.ExecContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), tenant.String()); err != nil {
			t.Fatalf("seed member: %v", err)
		}
		kind := "secondary"
		if i == 4 {
			kind = "primary"
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, $3)`,
			assetID.String(), u.String(), kind); err != nil {
			t.Fatalf("seed owner: %v", err)
		}
	}
	got, err := NewAccessControlRepository(&DB{DB: db}).ListAssetOwnersWithNames(ctx, tenant, assetID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("listed %d owners, want the cap of 3", len(got))
	}
	if got[0].OwnershipType().String() != "primary" {
		t.Fatalf("primary owner must survive the cap, first is %s", got[0].OwnershipType())
	}
}

// Role bindings of one team are capped.
func TestGroupRoleBindingList_Capped_DB(t *testing.T) {
	db, ctx := capTestDB(t)
	tenant := seedTestTenant(ctx, t, db)
	groupID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'g', $3)`,
		groupID.String(), tenant.String(), "g-"+groupID.String()); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	for i := 0; i < 5; i++ {
		rid := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO roles (id, tenant_id, slug, name) VALUES ($1, $2, $3, $4)`,
			rid.String(), tenant.String(), "r-"+rid.String(), "role-"+rid.String()); err != nil {
			t.Fatalf("seed role: %v", err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`,
			tenant.String(), groupID.String(), rid.String()); err != nil {
			t.Fatalf("seed binding: %v", err)
		}
	}
	got, err := NewGroupRoleBindingRepository(&DB{DB: db}).ListGroupRoles(ctx, tenant, groupID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("listed %d bindings, want the cap of 3", len(got))
	}
}
