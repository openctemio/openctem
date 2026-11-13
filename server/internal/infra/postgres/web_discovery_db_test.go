package postgres

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
)

// SECURITY: a derived list is built from one organization's rows only:
// tenant A's list for its origin holds A's sibling paths and none of tenant
// B's paths, even when B serves the same paths on more origins. Requires
// DATABASE_URL.
func TestWebDiscoveryDerivedInput_TenantIsolation(t *testing.T) {
	f := newWebFixture(t) // tenant A, origin https://a.example.com
	ctx := context.Background()
	repo := NewWebDiscoveryRepository(f.db)
	a2 := f.seedOrigin(t, f.tenant, "https://a2.example.com")
	a3 := f.seedOrigin(t, f.tenant, "https://a3.example.com")
	other := seedTestTenant(ctx, t, f.sqlDB)
	b1 := f.seedOrigin(t, other, "https://b1.example.com")
	b2 := f.seedOrigin(t, other, "https://b2.example.com")
	b3 := f.seedOrigin(t, other, "https://b3.example.com")

	if _, err := f.sqlDB.ExecContext(ctx, `UPDATE assets SET sub_type = 'http' WHERE tenant_id IN ($1, $2)`, f.tenant.String(), other.String()); err != nil {
		t.Fatal(err)
	}
	ep := func(origin, path string) webendpoint.Observation {
		return obs(t, ctis.Endpoint{Origin: origin, Path: path, StatusCode: 200})
	}
	f.record(t, f.tenant, f.origin, ep("https://a.example.com", "/index.php"), ep("https://a.example.com", "/api/v2/users"))
	f.record(t, f.tenant, a2, ep("https://a2.example.com", "/shared-a"))
	f.record(t, f.tenant, a3, ep("https://a3.example.com", "/shared-a"))
	for _, o := range []struct {
		id   shared.ID
		name string
	}{{b1, "https://b1.example.com"}, {b2, "https://b2.example.com"}, {b3, "https://b3.example.com"}} {
		f.record(t, other, o.id, ep(o.name, "/b-secret"), ep(o.name, "/index.php"))
	}

	in, err := repo.DerivedInput(ctx, f.tenant, "https://a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Own) != 2 {
		t.Fatalf("own rows %d, want 2", len(in.Own))
	}
	if len(in.Siblings) != 1 || in.Siblings[0].Template != "/shared-a" || in.Siblings[0].Origins != 2 {
		t.Fatalf("siblings %+v, want only tenant A's /shared-a on 2 origins", in.Siblings)
	}
	list := webendpoint.DerivedCandidates(in, nil, 0)
	for _, p := range list.Paths {
		if strings.Contains(p, "b-secret") {
			t.Fatalf("tenant A's derived list holds tenant B's path %s", p)
		}
	}
	if !slices.Contains(list.Paths, "/index.php.bak") || !slices.Contains(list.Paths, "/api/v1/users") {
		t.Fatalf("derived list %v", list.Paths)
	}

	// Tenant B asking for A's origin gets nothing.
	in, err = repo.DerivedInput(ctx, other, "https://a.example.com")
	if err != nil || len(in.Own)+len(in.Siblings)+len(in.SpecPaths) != 0 {
		t.Fatalf("tenant B read tenant A's origin: %+v, %v", in, err)
	}
}
