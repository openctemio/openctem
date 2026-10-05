package integration

// research/22 P0-10 (owner decision E6) on a migrated database: tenant
// self-service domain verification is EASM-only, tenant-isolated, gives no
// "already claimed" oracle, and names under an EASM-verified domain earn
// the strong verified-root rule; the SSO JIT gate ignores it.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

type easmTXT map[string][]string

func (r easmTXT) LookupTXT(_ context.Context, name string) ([]string, error) { return r[name], nil }

func TestEASMDomainVerification(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	res := easmTXT{}
	svc := domainverify.NewService(postgres.NewVerifiedDomainRepository(pg), res, nil)

	a, txtA, err := svc.AddEASMDomain(ctx, tenantA, "verify-it.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Tenant B adds the same domain: no conflict, no hint of A's row.
	b, txtB, err := svc.AddEASMDomain(ctx, tenantB, "verify-it.example.com")
	if err != nil {
		t.Fatalf("second tenant refused: %v", err)
	}
	if txtA.Value == txtB.Value {
		t.Fatal("two tenants got the same token")
	}
	// B cannot see, verify or delete A's row.
	if rows, _ := svc.List(ctx, tenantB); len(rows) != 1 || rows[0].ID() != b.ID() {
		t.Fatalf("tenant B sees %d rows", len(rows))
	}
	if _, err := svc.VerifyEASM(ctx, tenantB, a.ID()); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("B verified A's row: %v", err)
	}
	if _, err := svc.DeleteEASM(ctx, tenantB, a.ID()); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("B deleted A's row: %v", err)
	}

	// Only A publishes its record: A verifies, B does not.
	res[txtA.Host] = []string{txtA.Value}
	if vd, err := svc.VerifyEASM(ctx, tenantA, a.ID()); err != nil || !vd.IsVerified() {
		t.Fatalf("A verify: %v %v", vd, err)
	}
	if vd, err := svc.VerifyEASM(ctx, tenantB, b.ID()); err != nil || vd.IsVerified() {
		t.Fatalf("B verified with A's record: %v %v", vd, err)
	}
	stored, err := postgres.NewVerifiedDomainRepository(pg).GetByID(ctx, tenantA, a.ID())
	if err != nil || stored.Purpose() != verifieddomain.PurposeEASM || !stored.IsVerified() {
		t.Fatalf("stored: %+v %v", stored, err)
	}

	// The SSO JIT / SCIM gate ignores an EASM-purpose domain.
	if ok, err := svc.IsVerifiedDomain(ctx, tenantA.String(), "verify-it.example.com"); err != nil || ok {
		t.Fatalf("EASM verification admits SSO users: %v %v", ok, err)
	}
	// EASM counts it: names under it are under a verified domain for A only.
	seeds := postgres.NewEASMSeedRepository(pg)
	namesA, err := seeds.VerifiedDomainNames(ctx, tenantA)
	if err != nil || len(namesA) != 1 || namesA[0] != "verify-it.example.com" {
		t.Fatalf("A verified names = %v %v", namesA, err)
	}
	if namesB, _ := seeds.VerifiedDomainNames(ctx, tenantB); len(namesB) != 0 {
		t.Fatalf("B verified names = %v", namesB)
	}

	// Removing the record: the 12-hour re-check marks it failed.
	delete(res, txtA.Host)
	if _, err := svc.ReverifyDue(ctx, 0, 100); err != nil {
		t.Fatal(err)
	}
	if vd, _ := postgres.NewVerifiedDomainRepository(pg).GetByID(ctx, tenantA, a.ID()); vd.IsVerified() {
		t.Fatal("a lost record still counts as verified")
	}
	if namesA, _ := seeds.VerifiedDomainNames(ctx, tenantA); len(namesA) != 0 {
		t.Fatalf("lost domain still verified for EASM: %v", namesA)
	}
}
