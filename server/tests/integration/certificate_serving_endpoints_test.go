package integration

// AssetRelationshipRepository.ServingEndpoints: the endpoints that served a
// certificate come only from the tenant's own live assets on both ends of the
// serves_certificate edge, never cross tenants, skip deleted assets and other
// relationship types, and are bounded per certificate.

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCertificateServingEndpoints_TenantPinned(t *testing.T) {
	db := testdb.PrivateDatabase(t, "certserving", "../../migrations")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantA = "a1111111-1111-4111-8111-111111111111"
		tenantB = "b2222222-2222-4222-8222-222222222222"
		certA   = "0a000000-0000-4000-8000-000000000001"
		svcA1   = "0a000000-0000-4000-8000-000000000002"
		svcA2   = "0a000000-0000-4000-8000-000000000003"
		svcGone = "0a000000-0000-4000-8000-000000000004"
		svcExp  = "0a000000-0000-4000-8000-000000000005"
		certA2  = "0a000000-0000-4000-8000-000000000006"
		certB   = "0b000000-0000-4000-8000-000000000001"
		svcB    = "0b000000-0000-4000-8000-000000000002"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'cert-serv-a'), ($2, 'b', 'cert-serv-b')`, tenantA, tenantB)
	asset := func(id, tenant, name, typ string) {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`, id, tenant, name, typ)
	}
	edge := func(tenant, src, dst, typ string) {
		exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, $4)`,
			tenant, src, dst, typ)
	}
	asset(certA, tenantA, "c0ffee01", "certificate")
	asset(certA2, tenantA, "c0ffee02", "certificate")
	asset(svcA1, tenantA, "b.example.com:443", "service")
	asset(svcA2, tenantA, "a.example.com:443", "service")
	asset(svcGone, tenantA, "gone.example.com:443", "service")
	asset(svcExp, tenantA, "exposes.example.com:443", "service")
	asset(certB, tenantB, "c0ffee01", "certificate")
	asset(svcB, tenantB, "b.example.com:443", "service")
	exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, svcGone)
	edge(tenantA, svcA1, certA, "serves_certificate")
	edge(tenantA, svcA2, certA, "serves_certificate")
	edge(tenantA, svcGone, certA, "serves_certificate")
	edge(tenantA, svcExp, certA, "exposes") // not a serves edge
	edge(tenantA, certA2, certA, "serves_certificate")
	edge(tenantB, svcB, certB, "serves_certificate")

	repo := postgres.NewAssetRelationshipRepository(&postgres.DB{DB: db})
	ctx := context.Background()
	ids := func(ss ...string) []shared.ID {
		var out []shared.ID
		for _, s := range ss {
			out = append(out, shared.MustIDFromString(s))
		}
		return out
	}
	got, err := repo.ServingEndpoints(ctx, shared.MustIDFromString(tenantA), ids(certA, certA2, certB))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, id := range got[certA] {
		names = append(names, id.String())
	}
	// By endpoint name: a.example.com then b.example.com. The deleted
	// service, the exposes edge and a certificate as source are left out.
	if want := []string{svcA2, svcA1}; !slices.Equal(names, want) {
		t.Errorf("endpoints of the certificate = %v, want %v", names, want)
	}
	if len(got[certA2]) != 0 {
		t.Errorf("a certificate with no serving edge got endpoints: %v", got[certA2])
	}
	// Another tenant's certificate id asked as tenant A: nothing.
	if len(got[certB]) != 0 {
		t.Errorf("tenant B's certificate answered for tenant A: %v", got[certB])
	}
	other, err := repo.ServingEndpoints(ctx, shared.MustIDFromString(tenantB), ids(certA, certB))
	if err != nil {
		t.Fatal(err)
	}
	if len(other[certA]) != 0 || len(other[certB]) != 1 || other[certB][0].String() != svcB {
		t.Errorf("tenant B sees %v", other)
	}
	// An edge across tenants cannot exist (the composite foreign keys); the
	// insert is refused.
	if _, err := db.Exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'serves_certificate')`,
		tenantA, svcB, certA); err == nil {
		t.Error("an edge from another tenant's asset was accepted")
	}

	// Bounded per certificate.
	for i := 0; i < 205; i++ {
		id := fmt.Sprintf("0c000000-0000-4000-8000-%012d", i)
		asset(id, tenantA, fmt.Sprintf("h%03d.example.com:443", i), "service")
		edge(tenantA, id, certA2, "serves_certificate")
	}
	big, err := repo.ServingEndpoints(ctx, shared.MustIDFromString(tenantA), ids(certA2))
	if err != nil {
		t.Fatal(err)
	}
	if len(big[certA2]) != 200 {
		t.Errorf("%d endpoints, want the cap of 200", len(big[certA2]))
	}
}
