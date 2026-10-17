package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/role"
)

// A custom role created from a template keeps its template origin through
// create, get, list and update; another organization never reads it.
func TestRoleRepository_TemplateOriginRoundTrip(t *testing.T) {
	db := openRoleRaceDB(t)
	ctx := context.Background()
	tenantA, tenantB := seedTenant(ctx, t, db), seedTenant(ctx, t, db)
	repo := NewRoleRepository(db)
	tid, _ := role.ParseID(tenantA.String())
	other, _ := role.ParseID(tenantB.String())

	r := role.New(tid, "tpl-analyst", "Analyst", "", 10, false, []string{"findings:read", "assets:read"}, role.NewID())
	// created_by references users; a role made by a system path has none.
	r = role.Reconstruct(r.ID(), r.TenantID(), r.Slug(), r.Name(), "", false, 10, false, r.Permissions(), r.CreatedAt(), r.UpdatedAt(), nil)
	r.SetTemplate(&role.TemplateOrigin{ID: "security-analyst", Version: 1, Permissions: []string{"findings:read", "assets:read", "findings:write"}})
	if err := repo.Create(ctx, r); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GetByID(ctx, tid, r.ID())
	if err != nil {
		t.Fatal(err)
	}
	o := got.Template()
	if o == nil || o.ID != "security-analyst" || o.Version != 1 || len(o.Permissions) != 3 {
		t.Fatalf("origin after get = %+v", o)
	}
	list, err := repo.ListForTenant(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	idx := slices.IndexFunc(list, func(x *role.Role) bool { return x.ID() == r.ID() })
	if idx < 0 || list[idx].Template() == nil {
		t.Fatalf("list lost the origin")
	}

	got.SetTemplate(&role.TemplateOrigin{ID: "security-analyst", Version: 2, Permissions: []string{"findings:read"}})
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := repo.GetByID(ctx, tid, r.ID())
	if o := again.Template(); o == nil || o.Version != 2 || !slices.Equal(o.Permissions, []string{"findings:read"}) {
		t.Errorf("origin after update = %+v", o)
	}

	if _, err := repo.GetByID(ctx, other, r.ID()); !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("another organization reads the role: %v", err)
	}
	for _, x := range mustList(ctx, t, repo, other) {
		if x.ID() == r.ID() {
			t.Errorf("another organization lists the role")
		}
	}

	// A role built from scratch has no origin, and the database refuses a
	// half-recorded one.
	plain := role.Reconstruct(role.NewID(), &tid, "tpl-plain", "Plain", "", false, 10, false, nil, r.CreatedAt(), r.UpdatedAt(), nil)
	if err := repo.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if p, _ := repo.GetByID(ctx, tid, plain.ID()); p.Template() != nil {
		t.Errorf("plain role has an origin: %+v", p.Template())
	}
	if _, err := db.ExecContext(ctx, `UPDATE roles SET template_id = 'auditor' WHERE id = $1`, plain.ID().String()); err == nil {
		t.Errorf("a template id without a version was stored")
	}
}

func mustList(ctx context.Context, t *testing.T, repo *RoleRepository, tid role.ID) []*role.Role {
	t.Helper()
	l, err := repo.ListForTenant(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
