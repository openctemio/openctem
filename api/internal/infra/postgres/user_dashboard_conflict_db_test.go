package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A second dashboard with a name the user already has is a conflict (409),
// not an internal error (500); creating and renaming alike. The name is
// unique per user, so another user (or tenant) may use it.
func TestUserDashboard_DuplicateNameIsConflict_DB(t *testing.T) {
	ctx := context.Background()
	sqldb := openGroupsDB(t)
	repo := NewUserDashboardRepository(&DB{DB: sqldb})

	tenant, other := seedTestTenant(ctx, t, sqldb), seedTestTenant(ctx, t, sqldb)
	user, colleague := seedGroupsUser(ctx, t, sqldb, "example.com"), seedGroupsUser(ctx, t, sqldb, "example.com")

	mk := func(tid, uid shared.ID, name string) *dashboard.Dashboard {
		t.Helper()
		d, err := dashboard.NewDashboard(tid, uid, name, "", 0, nil)
		if err != nil {
			t.Fatalf("NewDashboard: %v", err)
		}
		return d
	}
	if err := repo.Create(ctx, mk(tenant, user, "Ops")); err != nil {
		t.Fatalf("create: %v", err)
	}
	err := repo.Create(ctx, mk(tenant, user, "Ops"))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate create: %v, want ErrConflict", err)
	}
	if err := repo.Create(ctx, mk(tenant, colleague, "Ops")); err != nil {
		t.Fatalf("another user with the same name: %v", err)
	}
	if err := repo.Create(ctx, mk(other, user, "Ops")); err != nil {
		t.Fatalf("another tenant with the same name: %v", err)
	}

	second := mk(tenant, user, "Risk")
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("create second: %v", err)
	}
	if err := second.Update("Ops", "", 0, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := repo.Update(ctx, second); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("rename onto a taken name: %v, want ErrConflict", err)
	}
}
