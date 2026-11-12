package domainverify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

func publish(r *mockResolver, vd *verifieddomain.VerifiedDomain) {
	txt := Instructions(vd.Domain(), vd.VerificationToken())
	if r.records == nil {
		r.records = map[string][]string{}
	}
	r.records[txt.Host] = []string{txt.Value}
}

// research/22 E6: a domain the tenant verifies itself is EASM-only; it
// never admits SSO JIT or SCIM users. The same domain set up by a platform
// administrator does.
func TestEASMVerification_NeverAdmitsSSO(t *testing.T) {
	ctx := context.Background()
	res := &mockResolver{}
	svc := NewService(newMemRepo(), res, nil)
	tenant := shared.NewID()

	vd, txt, err := svc.AddEASMDomain(ctx, tenant, "Example.COM")
	if err != nil || vd.Purpose() != verifieddomain.PurposeEASM || txt.Value == "" {
		t.Fatalf("add: %v %v %+v", vd, err, txt)
	}
	publish(res, vd)
	got, err := svc.VerifyEASM(ctx, tenant, vd.ID())
	if err != nil || !got.IsVerified() {
		t.Fatalf("verify: %v %v", got, err)
	}
	if ok, err := svc.IsVerifiedDomain(ctx, tenant.String(), "example.com"); err != nil || ok {
		t.Fatalf("EASM verification admitted SSO users: %v %v", ok, err)
	}

	// The administrator makes it an SSO domain: same row, verification kept.
	adm, _, err := svc.AddDomain(ctx, tenant, "example.com")
	if err != nil || adm.ID() != vd.ID() || adm.Purpose() != verifieddomain.PurposeSSO || !adm.IsVerified() {
		t.Fatalf("admin promote: %+v %v", adm, err)
	}
	if ok, _ := svc.IsVerifiedDomain(ctx, tenant.String(), "example.com"); !ok {
		t.Fatal("an SSO domain does not admit users")
	}
	// From then on the tenant can neither re-check nor delete it.
	if _, err := svc.VerifyEASM(ctx, tenant, vd.ID()); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("tenant re-checked an SSO row: %v", err)
	}
	if _, err := svc.DeleteEASM(ctx, tenant, vd.ID()); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("tenant deleted an SSO row: %v", err)
	}
}

func TestAddEASMDomain_Refusals(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newMemRepo(), &mockResolver{}, nil)
	tenant := shared.NewID()
	for _, d := range []string{"co.uk", "com", "github.io", "gmail.com", "x.onmicrosoft.com", "bad domain", "*.example.com", "http://example.com"} {
		if _, _, err := svc.AddEASMDomain(ctx, tenant, d); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
	if _, _, err := svc.AddEASMDomain(ctx, tenant, "example.org"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AddEASMDomain(ctx, tenant, "EXAMPLE.org."); !errors.Is(err, verifieddomain.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	// Another tenant adds the same domain: allowed, separate row, no hint.
	other := shared.NewID()
	if _, _, err := svc.AddEASMDomain(ctx, other, "example.org"); err != nil {
		t.Fatalf("second tenant refused: %v", err)
	}
}

// Tenant isolation: another tenant's row is not found for verify or delete.
func TestEASMVerification_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newMemRepo(), &mockResolver{}, nil)
	a, b := shared.NewID(), shared.NewID()
	vd, _, err := svc.AddEASMDomain(ctx, a, "example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyEASM(ctx, b, vd.ID()); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("B verified A's row: %v", err)
	}
	if _, err := svc.DeleteEASM(ctx, b, vd.ID()); !errors.Is(err, verifieddomain.ErrNotFound) {
		t.Fatalf("B deleted A's row: %v", err)
	}
}

// At most MaxEASMVerifyPerHour checks per tenant per hour; other tenants
// keep their own budget; the window slides.
func TestVerifyEASM_RateLimited(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newMemRepo(), &mockResolver{}, nil)
	lim := NewWindowLimiter(MaxEASMVerifyPerHour, time.Hour)
	now := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	lim.now = func() time.Time { return now }
	svc.SetVerifyLimiter(lim)
	a, b := shared.NewID(), shared.NewID()
	va, _, _ := svc.AddEASMDomain(ctx, a, "a.example")
	vb, _, _ := svc.AddEASMDomain(ctx, b, "b.example")
	for i := 0; i < MaxEASMVerifyPerHour; i++ {
		if _, err := svc.VerifyEASM(ctx, a, va.ID()); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
	}
	if _, err := svc.VerifyEASM(ctx, a, va.ID()); !errors.Is(err, ErrVerifyRateLimited) {
		t.Fatalf("check over the limit: %v", err)
	}
	if _, err := svc.VerifyEASM(ctx, b, vb.ID()); err != nil {
		t.Fatalf("tenant B limited by A: %v", err)
	}
	now = now.Add(61 * time.Minute)
	if _, err := svc.VerifyEASM(ctx, a, va.ID()); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}
